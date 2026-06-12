use crate::{ForwardRule, add_forward_rule, delete_forward_rule, list_forward_rules};
use anyhow::Context as _;
use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionInfo {
    pub proto: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub nat_port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ManagerMessage {
    #[serde(rename = "report")]
    Report {
        node_id: String,
        group: String,
        hostname: String,
        rules: Vec<ForwardRule>,
    },
    #[serde(rename = "response")]
    Response {
        command_id: String,
        status: String,
        error_message: Option<String>,
    },
    #[serde(rename = "query_response")]
    QueryResponse {
        command_id: String,
        status: String,
        sessions: Vec<SessionInfo>,
        error_message: Option<String>,
    },
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(tag = "type")]
pub enum NodeCommand {
    #[serde(rename = "add_rule")]
    AddRule {
        command_id: String,
        proto: String,
        local_port: u32,
        forward_ip: String,
        forward_port: u16,
    },
    #[serde(rename = "delete_rule")]
    DeleteRule {
        command_id: String,
        proto: String,
        local_port: u32,
    },
    #[serde(rename = "query_session")]
    QuerySession {
        command_id: String,
        src_ip: String,
        dst_ip: String,
    },
}

fn get_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string())
}

async fn query_bpf_sessions(
    ebpf: &Mutex<aya::Ebpf>,
    src_ip_str: &str,
    dst_ip_str: &str,
) -> anyhow::Result<Vec<SessionInfo>> {
    use aya::maps::HashMap;
    use forward_common::{SessionKey, SessionVal};
    use std::net::Ipv4Addr;

    let src_ip: Ipv4Addr = src_ip_str.parse().context("invalid src_ip")?;
    let dst_ip: Ipv4Addr = dst_ip_str.parse().context("invalid dst_ip")?;

    let query_src_u32 = u32::from(src_ip).to_be();
    let query_dst_u32 = u32::from(dst_ip).to_be();

    let mut found = Vec::new();
    let mut ebpf_guard = ebpf.lock().await;
    let session_map = HashMap::<_, SessionKey, SessionVal>::try_from(
        ebpf_guard
            .map_mut("SESSION_MAP")
            .context("SESSION_MAP not found")?,
    )?;

    for item in session_map.iter() {
        if let Ok((key, val)) = item {
            if key.client_ip == query_src_u32 && key.target_ip == query_dst_u32 {
                let proto = if key.proto == 6 {
                    "tcp".to_string()
                } else {
                    "udp".to_string()
                };
                found.push(SessionInfo {
                    proto,
                    src_port: u16::from_be(key.client_port),
                    dst_port: u16::from_be(key.target_port),
                    nat_port: u16::from_be(val.nat_port),
                });
            }
        }
    }
    Ok(found)
}

pub fn spawn_manager_client(
    manager_url: String,
    node_id: String,
    group: String,
    ebpf: Arc<Mutex<aya::Ebpf>>,
    rules_path: Option<String>,
) {
    tokio::spawn(async move {
        let hostname = get_hostname();
        loop {
            let mut normalized_url = manager_url.clone();
            if !normalized_url.ends_with("/ws") {
                if normalized_url.ends_with('/') {
                    normalized_url.push_str("ws");
                } else {
                    normalized_url.push_str("/ws");
                }
            }

            let url_with_query = format!(
                "{}?node_id={}&group={}&hostname={}",
                normalized_url,
                urlencoding::encode(&node_id),
                urlencoding::encode(&group),
                urlencoding::encode(&hostname)
            );

            info!("Connecting to manager at: {}", normalized_url);
            match connect_async(&url_with_query).await {
                Ok((ws_stream, _)) => {
                    info!("Connected to manager!");
                    let (mut write, mut read) = ws_stream.split();

                    // Send initial report
                    if let Ok(rules) = list_forward_rules(&ebpf).await {
                        let report = ManagerMessage::Report {
                            node_id: node_id.clone(),
                            group: group.clone(),
                            hostname: hostname.clone(),
                            rules,
                        };
                        if let Ok(txt) = serde_json::to_string(&report) {
                            let _ = write.send(Message::Text(txt.into())).await;
                        }
                    }

                    // Loop to receive commands
                    while let Some(msg_res) = read.next().await {
                        match msg_res {
                            Ok(Message::Text(txt)) => {
                                match serde_json::from_str::<NodeCommand>(&txt) {
                                    Ok(cmd) => match cmd {
                                        NodeCommand::AddRule {
                                            command_id,
                                            proto,
                                            local_port,
                                            forward_ip,
                                            forward_port,
                                        } => {
                                            let r = add_forward_rule(
                                                &ebpf,
                                                &proto,
                                                local_port,
                                                &forward_ip,
                                                forward_port,
                                            )
                                            .await;

                                            if r.is_ok() {
                                                if let Some(ref path) = rules_path {
                                                    if let Ok(rules) =
                                                        list_forward_rules(&ebpf).await
                                                    {
                                                        let _ =
                                                            crate::rule::save_rules(path, &rules);
                                                    }
                                                }
                                            }

                                            let response = match r {
                                                Ok(_) => ManagerMessage::Response {
                                                    command_id: command_id.clone(),
                                                    status: "success".to_string(),
                                                    error_message: None,
                                                },
                                                Err(e) => ManagerMessage::Response {
                                                    command_id: command_id.clone(),
                                                    status: "error".to_string(),
                                                    error_message: Some(format!("{e:#}")),
                                                },
                                            };

                                            if let Ok(txt) = serde_json::to_string(&response) {
                                                let _ = write.send(Message::Text(txt.into())).await;
                                            }

                                            if let Ok(rules) = list_forward_rules(&ebpf).await {
                                                let report = ManagerMessage::Report {
                                                    node_id: node_id.clone(),
                                                    group: group.clone(),
                                                    hostname: hostname.clone(),
                                                    rules,
                                                };
                                                if let Ok(txt) = serde_json::to_string(&report) {
                                                    let _ =
                                                        write.send(Message::Text(txt.into())).await;
                                                }
                                            }
                                        }
                                        NodeCommand::DeleteRule {
                                            command_id,
                                            proto,
                                            local_port,
                                        } => {
                                            let r = delete_forward_rule(&ebpf, &proto, local_port)
                                                .await;

                                            if r.is_ok() {
                                                if let Some(ref path) = rules_path {
                                                    if let Ok(rules) =
                                                        list_forward_rules(&ebpf).await
                                                    {
                                                        let _ =
                                                            crate::rule::save_rules(path, &rules);
                                                    }
                                                }
                                            }

                                            let response = match r {
                                                Ok(_) => ManagerMessage::Response {
                                                    command_id: command_id.clone(),
                                                    status: "success".to_string(),
                                                    error_message: None,
                                                },
                                                Err(e) => ManagerMessage::Response {
                                                    command_id: command_id.clone(),
                                                    status: "error".to_string(),
                                                    error_message: Some(format!("{e:#}")),
                                                },
                                            };

                                            if let Ok(txt) = serde_json::to_string(&response) {
                                                let _ = write.send(Message::Text(txt.into())).await;
                                            }

                                            if let Ok(rules) = list_forward_rules(&ebpf).await {
                                                let report = ManagerMessage::Report {
                                                    node_id: node_id.clone(),
                                                    group: group.clone(),
                                                    hostname: hostname.clone(),
                                                    rules,
                                                };
                                                if let Ok(txt) = serde_json::to_string(&report) {
                                                    let _ =
                                                        write.send(Message::Text(txt.into())).await;
                                                }
                                            }
                                        }
                                        NodeCommand::QuerySession {
                                            command_id,
                                            src_ip,
                                            dst_ip,
                                        } => {
                                            let r =
                                                query_bpf_sessions(&ebpf, &src_ip, &dst_ip).await;
                                            let response = match r {
                                                Ok(sessions) => ManagerMessage::QueryResponse {
                                                    command_id,
                                                    status: "success".to_string(),
                                                    sessions,
                                                    error_message: None,
                                                },
                                                Err(e) => ManagerMessage::QueryResponse {
                                                    command_id,
                                                    status: "error".to_string(),
                                                    sessions: Vec::new(),
                                                    error_message: Some(format!("{e:#}")),
                                                },
                                            };
                                            if let Ok(txt) = serde_json::to_string(&response) {
                                                let _ = write.send(Message::Text(txt.into())).await;
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        error!("Failed to parse command JSON: {e:#}");
                                    }
                                }
                            }
                            Ok(Message::Close(_)) => {
                                warn!("Manager closed connection");
                                break;
                            }
                            Ok(_) => {}
                            Err(e) => {
                                error!("Websocket read error: {e:#}");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to connect to manager: {e:#}");
                }
            }

            info!("Retrying connection in 5 seconds...");
            sleep(Duration::from_secs(5)).await;
        }
    });
}
