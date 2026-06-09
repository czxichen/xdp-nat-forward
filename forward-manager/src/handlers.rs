use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;

use crate::types::{
    AppState, ClientMessage, ConnectedNode, ConnectedNodeInfo, WsParams,
};

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, params, state))
}

pub async fn handle_socket(socket: axum::extract::ws::WebSocket, params: WsParams, state: AppState) {
    let (sender, mut receiver) = socket.split();
    let node_id = params.node_id.clone();

    log::info!(
        "Node connected: {} (group: {}, host: {})",
        node_id,
        params.group,
        params.hostname
    );

    {
        let mut nodes = state.nodes.lock().await;
        nodes.insert(
            node_id.clone(),
            ConnectedNode {
                node_id: node_id.clone(),
                group: params.group.clone(),
                hostname: params.hostname.clone(),
                rules: Vec::new(),
                ws_sender: sender,
            },
        );
    }

    // Message loop
    while let Some(msg_res) = receiver.next().await {
        match msg_res {
            Ok(axum::extract::ws::Message::Text(txt)) => {
                match serde_json::from_str::<ClientMessage>(&txt) {
                    Ok(ClientMessage::Report {
                        node_id: r_node_id,
                        group,
                        hostname,
                        rules,
                    }) => {
                        let mut nodes = state.nodes.lock().await;
                        if let Some(node) = nodes.get_mut(&r_node_id) {
                            node.rules = rules;
                            node.group = group;
                            node.hostname = hostname;
                            log::info!("Updated rule report for node: {}", r_node_id);
                        }
                    }
                    Ok(ClientMessage::Response {
                        command_id,
                        status,
                        error_message,
                    }) => {
                        log::info!(
                            "Command response received: {} (status: {:?}, error: {:?})",
                            command_id,
                            status,
                            error_message
                        );
                    }
                    Err(e) => {
                        log::error!("Error decoding client message: {e:#}");
                    }
                }
            }
            Ok(axum::extract::ws::Message::Close(_)) => {
                break;
            }
            Ok(_) => {}
            Err(e) => {
                log::error!("Websocket receiver error for node {}: {:#}", node_id, e);
                break;
            }
        }
    }

    // Cleanup on disconnect
    log::info!("Node disconnected: {}", node_id);
    let mut nodes = state.nodes.lock().await;
    nodes.remove(&node_id);
}

pub async fn get_nodes(State(state): State<AppState>) -> Json<Vec<ConnectedNodeInfo>> {
    let nodes = state.nodes.lock().await;
    let list: Vec<ConnectedNodeInfo> = nodes
        .values()
        .map(|node| ConnectedNodeInfo {
            node_id: node.node_id.clone(),
            group: node.group.clone(),
            hostname: node.hostname.clone(),
            rules: node.rules.clone(),
        })
        .collect();
    Json(list)
}

#[derive(Deserialize)]
pub struct AddRuleRequestPayload {
    pub group: String,
    pub node_ids: Option<Vec<String>>,
    pub proto: String,
    pub local_port: u32,
    pub forward_ip: String,
    pub forward_port: u16,
}

pub async fn add_rule(
    State(state): State<AppState>,
    Json(payload): Json<AddRuleRequestPayload>,
) -> Result<Json<String>, (StatusCode, String)> {
    let mut nodes = state.nodes.lock().await;
    let command_id = format!("add-{}", tokio::time::Instant::now().elapsed().as_nanos());

    let command = serde_json::json!({
        "type": "add_rule",
        "command_id": command_id,
        "proto": payload.proto,
        "local_port": payload.local_port,
        "forward_ip": payload.forward_ip,
        "forward_port": payload.forward_port
    });

    let command_str = serde_json::to_string(&command).unwrap();
    let mut targets_sent = 0;

    for node in nodes.values_mut() {
        if node.group == payload.group {
            let matches_node_filter = match &payload.node_ids {
                Some(ids) => ids.contains(&node.node_id),
                None => true,
            };

            if matches_node_filter {
                log::info!("Sending add_rule to node: {}", node.node_id);
                let _ = node
                    .ws_sender
                    .send(axum::extract::ws::Message::Text(command_str.clone().into()))
                    .await;
                targets_sent += 1;
            }
        }
    }

    Ok(Json(format!("Sent add command to {} nodes", targets_sent)))
}

#[derive(Deserialize)]
pub struct DeleteRuleRequestPayload {
    pub group: String,
    pub node_ids: Option<Vec<String>>,
    pub proto: String,
    pub local_port: u32,
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Json(payload): Json<DeleteRuleRequestPayload>,
) -> Result<Json<String>, (StatusCode, String)> {
    let mut nodes = state.nodes.lock().await;
    let command_id = format!("del-{}", tokio::time::Instant::now().elapsed().as_nanos());

    let command = serde_json::json!({
        "type": "delete_rule",
        "command_id": command_id,
        "proto": payload.proto,
        "local_port": payload.local_port
    });

    let command_str = serde_json::to_string(&command).unwrap();
    let mut targets_sent = 0;

    for node in nodes.values_mut() {
        if node.group == payload.group {
            let matches_node_filter = match &payload.node_ids {
                Some(ids) => ids.contains(&node.node_id),
                None => true,
            };

            if matches_node_filter {
                log::info!("Sending delete_rule to node: {}", node.node_id);
                let _ = node
                    .ws_sender
                    .send(axum::extract::ws::Message::Text(command_str.clone().into()))
                    .await;
                targets_sent += 1;
            }
        }
    }

    Ok(Json(format!("Sent delete command to {} nodes", targets_sent)))
}
