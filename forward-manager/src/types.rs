use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::SplitSink;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionInfo {
    pub proto: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub nat_port: u16,
}

#[derive(Clone)]
pub struct AppState {
    pub nodes: Arc<Mutex<HashMap<String, ConnectedNode>>>,
    pub pending_queries: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>>>,
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
    #[serde(rename = "query_response")]
    QueryResponse {
        command_id: String,
        status: String,
        sessions: Vec<SessionInfo>,
        error_message: Option<String>,
    },
}

#[derive(Deserialize)]
pub struct WsParams {
    pub node_id: String,
    pub group: String,
    pub hostname: String,
}
