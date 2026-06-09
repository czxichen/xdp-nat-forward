use axum::{
    Json, Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ForwardRule {
    pub proto: u32,
    pub local_port: u32,
    pub forward_ip: std::net::Ipv4Addr,
    pub forward_port: u16,
    pub forward_mac: [u8; 6],
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectedNodeInfo {
    pub node_id: String,
    pub group: String,
    pub hostname: String,
    pub rules: Vec<ForwardRule>,
}

pub struct ConnectedNode {
    pub node_id: String,
    pub group: String,
    pub hostname: String,
    pub rules: Vec<ForwardRule>,
    pub ws_sender: SplitSink<WebSocket, Message>,
}

#[derive(Clone)]
pub struct AppState {
    pub nodes: Arc<Mutex<HashMap<String, ConnectedNode>>>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ClientMessage {
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
}

#[derive(Deserialize)]
struct WsParams {
    node_id: String,
    group: String,
    hostname: String,
}

#[derive(Parser, Debug)]
#[clap(name = "forward-manager", about = "NAT Forward Rules Manager")]
struct Opt {
    #[clap(short, long, default_value = "127.0.0.1:9000")]
    addr: String,

    #[clap(
        short,
        long,
        alias = "static_dir",
        help = "Path to the static files directory (e.g. frontend/dist)"
    )]
    static_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let state = AppState {
        nodes: Arc::new(Mutex::new(HashMap::new())),
    };

    let serve_dir = ServeDir::new(&opt.static_dir)
        .fallback(ServeDir::new(&opt.static_dir).append_index_html_on_directories(true));

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/nodes", get(get_nodes))
        .route("/api/rules/add", post(add_rule))
        .route("/api/rules/delete", post(delete_rule))
        .fallback_service(serve_dir)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&opt.addr).await?;
    log::info!("Rules Manager listening on http://{}", opt.addr);

    axum::serve(listener, app).await?;

    return Ok(());
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, params, state))
}

async fn handle_socket(socket: WebSocket, params: WsParams, state: AppState) {
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
            Ok(Message::Text(txt)) => match serde_json::from_str::<ClientMessage>(&txt) {
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
            },
            Ok(Message::Close(_)) => {
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

async fn get_nodes(State(state): State<AppState>) -> Json<Vec<ConnectedNodeInfo>> {
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
struct AddRuleRequestPayload {
    group: String,
    node_ids: Option<Vec<String>>,
    proto: String,
    local_port: u32,
    forward_ip: String,
    forward_port: u16,
}

async fn add_rule(
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
                    .send(Message::Text(command_str.clone().into()))
                    .await;
                targets_sent += 1;
            }
        }
    }

    Ok(Json(format!("Sent add command to {} nodes", targets_sent)))
}

#[derive(Deserialize)]
struct DeleteRuleRequestPayload {
    group: String,
    node_ids: Option<Vec<String>>,
    proto: String,
    local_port: u32,
}

async fn delete_rule(
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
                    .send(Message::Text(command_str.clone().into()))
                    .await;
                targets_sent += 1;
            }
        }
    }

    Ok(Json(format!(
        "Sent delete command to {} nodes",
        targets_sent
    )))
}
