use crate::{
    Command, TimeoutsState, add_forward_rule, delete_forward_rule, list_forward_rules, set_timeout,
};
use anyhow::Context as _;
use log::info;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

async fn handle_command(line: String, ebpf: &Mutex<aya::Ebpf>, timeouts: &TimeoutsState) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return "ERR: empty command\n".to_string();
    }
    match parts[0].to_uppercase().as_str() {
        "ADD" => {
            if parts.len() != 5 {
                return "ERR: ADD requires 4 arguments: proto, local_port, forward_ip, forward_port\n"
                    .to_string();
            }
            let proto_str = parts[1];
            let local_port: u32 = match parts[2].parse() {
                Ok(p) => p,
                Err(_) => return "ERR: invalid local_port\n".to_string(),
            };
            let forward_ip_str = parts[3];
            let forward_port: u16 = match parts[4].parse() {
                Ok(p) => p,
                Err(_) => return "ERR: invalid forward_port\n".to_string(),
            };

            match add_forward_rule(ebpf, proto_str, local_port, forward_ip_str, forward_port).await
            {
                Ok(forward_mac) => {
                    format!(
                        "OK: mapped {}:{} -> {}:{} ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})\n",
                        proto_str.to_lowercase(),
                        local_port,
                        forward_ip_str,
                        forward_port,
                        forward_mac[0],
                        forward_mac[1],
                        forward_mac[2],
                        forward_mac[3],
                        forward_mac[4],
                        forward_mac[5]
                    )
                }
                Err(e) => format!("ERR: {e:#}\n"),
            }
        }
        "DEL" => {
            if parts.len() != 3 {
                return "ERR: DEL requires 2 arguments: proto, local_port\n".to_string();
            }
            let proto_str = parts[1];
            let local_port: u32 = match parts[2].parse() {
                Ok(p) => p,
                Err(_) => return "ERR: invalid local_port\n".to_string(),
            };

            match delete_forward_rule(ebpf, proto_str, local_port).await {
                Ok(()) => {
                    format!(
                        "OK: deleted forwarding mapping for {} port {}\n",
                        proto_str.to_lowercase(),
                        local_port
                    )
                }
                Err(e) => format!("ERR: {e:#}\n"),
            }
        }
        "LIST" => match list_forward_rules(ebpf).await {
            Ok(rules) => {
                let mut output = String::new();
                output.push_str("PROTO\tLOCAL_PORT\tFORWARD_IP\tFORWARD_PORT\tFORWARD_MAC\n");
                for rule in rules {
                    let proto_str = if rule.proto == 6 { "tcp" } else { "udp" };
                    output.push_str(&format!(
                        "{}\t{}\t{}\t{}\t{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                        proto_str,
                        rule.local_port,
                        rule.forward_ip,
                        rule.forward_port,
                        rule.forward_mac[0],
                        rule.forward_mac[1],
                        rule.forward_mac[2],
                        rule.forward_mac[3],
                        rule.forward_mac[4],
                        rule.forward_mac[5]
                    ));
                }
                output
            }
            Err(e) => format!("ERR: failed to list rules: {e:#}\n"),
        },
        "TIMEOUT" => {
            if parts.len() != 3 {
                return "ERR: TIMEOUT requires 2 arguments: proto, seconds\n".to_string();
            }
            let proto_str = parts[1];
            let seconds: u64 = match parts[2].parse() {
                Ok(s) => s,
                Err(_) => return "ERR: invalid seconds\n".to_string(),
            };

            match set_timeout(timeouts, proto_str, seconds) {
                Ok(()) => format!(
                    "OK: set {} timeout to {} seconds\n",
                    proto_str.to_lowercase(),
                    seconds
                ),
                Err(e) => format!("ERR: {e:#}\n"),
            }
        }
        _ => format!("ERR: unknown command {}\n", parts[0]),
    }
}

pub async fn run_client(socket_path: &str, command: Command) -> anyhow::Result<()> {
    let cmd_str = match command {
        Command::Add {
            proto,
            local_port,
            forward_ip,
            forward_port,
        } => {
            format!(
                "ADD {} {} {} {}\n",
                proto, local_port, forward_ip, forward_port
            )
        }
        Command::Del { proto, local_port } => {
            format!("DEL {} {}\n", proto, local_port)
        }
        Command::List => "LIST\n".to_string(),
        Command::Timeout { proto, seconds } => {
            format!("TIMEOUT {} {}\n", proto, seconds)
        }
    };

    let mut stream = UnixStream::connect(socket_path).await.context(format!(
        "failed to connect to daemon socket at {}",
        socket_path
    ))?;

    stream.write_all(cmd_str.as_bytes()).await?;
    stream.shutdown().await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    info!("{}", response);
    return Ok(());
}

pub async fn spawn_uds_server(
    socket_path: &str,
    ebpf: Arc<Mutex<aya::Ebpf>>,
    timeouts: Arc<TimeoutsState>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .context(format!("failed to bind to UDS socket at {socket_path}"))?;

    info!("Listening on UDS socket: {}", socket_path);

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let ebpf_ref = Arc::clone(&ebpf);
                let timeouts_ref = Arc::clone(&timeouts);
                tokio::spawn(async move {
                    let (rx, mut tx) = stream.into_split();
                    let reader = TokioBufReader::new(rx);
                    let mut lines = reader.lines();
                    if let Ok(Some(line)) = lines.next_line().await {
                        let response = handle_command(line, &ebpf_ref, &timeouts_ref).await;
                        let _ = tx.write_all(response.as_bytes()).await;
                    }
                });
            }
        }
    });
    return Ok(handle);
}
