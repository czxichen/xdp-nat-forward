use crate::{
    TimeoutsState, add_forward_rule, delete_forward_rule, list_forward_rules, set_timeout,
};
use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    routing::{delete, get, post},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub ebpf: Arc<Mutex<aya::Ebpf>>,
    pub timeouts: Arc<TimeoutsState>,
    pub secret: String,
}

#[derive(serde::Deserialize)]
pub struct AddRuleRequest {
    pub proto: String,
    pub local_port: u32,
    pub forward_ip: String,
    pub forward_port: u16,
}

#[derive(serde::Serialize)]
pub struct AddRuleResponse {
    pub status: String,
    pub forward_mac: String,
}

#[derive(serde::Serialize)]
pub struct RuleResponse {
    pub proto: String,
    pub local_port: u32,
    pub forward_ip: String,
    pub forward_port: u16,
    pub forward_mac: String,
}

#[derive(serde::Deserialize)]
pub struct TimeoutRequest {
    pub proto: String,
    pub seconds: u64,
}

async fn get_rules(
    State(state): State<AppState>,
) -> Result<Json<Vec<RuleResponse>>, (StatusCode, String)> {
    let rules = list_forward_rules(&state.ebpf).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to list rules: {e:#}"),
        )
    })?;

    let resp = rules
        .into_iter()
        .map(|r| RuleResponse {
            proto: if r.proto == 6 {
                "tcp".to_string()
            } else {
                "udp".to_string()
            },
            local_port: r.local_port,
            forward_ip: r.forward_ip.to_string(),
            forward_port: r.forward_port,
            forward_mac: format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                r.forward_mac[0],
                r.forward_mac[1],
                r.forward_mac[2],
                r.forward_mac[3],
                r.forward_mac[4],
                r.forward_mac[5]
            ),
        })
        .collect();

    Ok(Json(resp))
}

async fn add_rule(
    State(state): State<AppState>,
    Json(payload): Json<AddRuleRequest>,
) -> Result<Json<AddRuleResponse>, (StatusCode, String)> {
    match add_forward_rule(
        &state.ebpf,
        &payload.proto,
        payload.local_port,
        &payload.forward_ip,
        payload.forward_port,
    )
    .await
    {
        Ok(mac) => {
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
            Ok(Json(AddRuleResponse {
                status: "OK".to_string(),
                forward_mac: mac_str,
            }))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("failed to add rule: {e:#}"),
        )),
    }
}

async fn delete_rule(
    State(state): State<AppState>,
    Path((proto, local_port)): Path<(String, u32)>,
) -> Result<Json<String>, (StatusCode, String)> {
    match delete_forward_rule(&state.ebpf, &proto, local_port).await {
        Ok(()) => Ok(Json("OK".to_string())),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("failed to delete rule: {e:#}"),
        )),
    }
}

async fn update_timeout(
    State(state): State<AppState>,
    Json(payload): Json<TimeoutRequest>,
) -> Result<Json<String>, (StatusCode, String)> {
    match set_timeout(&state.timeouts, &payload.proto, payload.seconds) {
        Ok(()) => Ok(Json("OK".to_string())),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            format!("failed to set timeout: {e:#}"),
        )),
    }
}

type HmacSha256 = Hmac<Sha256>;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn verify_signature(
    secret: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    signature: &str,
) -> bool {
    let ts_parsed: u64 = match timestamp.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return false,
    };

    let diff = if now >= ts_parsed {
        now - ts_parsed
    } else {
        ts_parsed - now
    };

    if diff > 300 {
        return false;
    }

    let sig_bytes = match hex::decode(signature) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let data = format!("{}.{}.{}", timestamp, method, path);
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(data.as_bytes());
    let expected = mac.finalize().into_bytes();

    constant_time_eq(&sig_bytes, &expected)
}

async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();
    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let method = req.method().as_str();
    let path = req.uri().path();

    if verify_signature(&state.secret, timestamp, method, path, signature) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn spawn_http_server(
    addr: &str,
    ebpf: Arc<Mutex<aya::Ebpf>>,
    timeouts: Arc<TimeoutsState>,
    secret: String,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    if secret == "forward-secret-key" {
        log::warn!("Using default secret key 'forward-secret-key' is not secure in production!");
    }
    let state = AppState {
        ebpf,
        timeouts,
        secret,
    };
    let app = Router::new()
        .route("/rules", get(get_rules).post(add_rule))
        .route("/rules/{proto}/{local_port}", delete(delete_rule))
        .route("/timeout", post(update_timeout))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context(format!("failed to bind HTTP server to {addr}"))?;

    log::info!("HTTP server listening on: http://{}", addr);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    return Ok(handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"hello", b"helloo"));
    }

    #[test]
    fn test_signature_validation() {
        let secret = "my-test-secret-key";
        let path = "/rules";
        let method = "GET";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_str = now.to_string();

        // 1. Generate valid signature
        let payload = format!("{}.{}.{}", timestamp_str, method, path);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // 2. Verify valid signature
        assert!(verify_signature(secret, &timestamp_str, method, path, &signature));

        // 3. Verify incorrect signature fails
        assert!(!verify_signature(secret, &timestamp_str, method, path, "invalid-hex-sig"));
        assert!(!verify_signature(secret, &timestamp_str, method, path, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"));

        // 4. Verify incorrect method fails
        assert!(!verify_signature(secret, &timestamp_str, "POST", path, &signature));

        // 5. Verify incorrect path fails
        assert!(!verify_signature(secret, &timestamp_str, method, "/timeout", &signature));

        // 6. Verify incorrect secret fails
        assert!(!verify_signature("wrong-secret", &timestamp_str, method, path, &signature));

        // 7. Verify expired timestamp fails (>300 seconds diff)
        let expired_ts = (now - 305).to_string();
        let expired_payload = format!("{}.{}.{}", expired_ts, method, path);
        let mut mac_expired = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac_expired.update(expired_payload.as_bytes());
        let expired_sig = hex::encode(mac_expired.finalize().into_bytes());
        assert!(!verify_signature(secret, &expired_ts, method, path, &expired_sig));

        // 8. Verify future timestamp fails (>300 seconds diff)
        let future_ts = (now + 305).to_string();
        let future_payload = format!("{}.{}.{}", future_ts, method, path);
        let mut mac_future = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac_future.update(future_payload.as_bytes());
        let future_sig = hex::encode(mac_future.finalize().into_bytes());
        assert!(!verify_signature(secret, &future_ts, method, path, &future_sig));

        // 9. Verify marginally valid timestamp succeeds (e.g. 290 seconds diff)
        let border_ts = (now - 290).to_string();
        let border_payload = format!("{}.{}.{}", border_ts, method, path);
        let mut mac_border = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac_border.update(border_payload.as_bytes());
        let border_sig = hex::encode(mac_border.finalize().into_bytes());
        assert!(verify_signature(secret, &border_ts, method, path, &border_sig));
    }
}
