mod types;
mod handlers;

use axum::{
    Router,
    routing::{get, post},
};
use clap::Parser;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use types::AppState;
use handlers::{ws_handler, get_nodes, add_rule, delete_rule, query_sessions};

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
        pending_queries: Arc::new(Mutex::new(HashMap::new())),
    };

    let serve_dir = ServeDir::new(&opt.static_dir)
        .fallback(ServeDir::new(&opt.static_dir).append_index_html_on_directories(true));

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/nodes", get(get_nodes))
        .route("/api/rules/add", post(add_rule))
        .route("/api/rules/delete", post(delete_rule))
        .route("/api/sessions/query", post(query_sessions))
        .fallback_service(serve_dir)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&opt.addr).await?;
    log::info!("Rules Manager listening on http://{}", opt.addr);

    axum::serve(listener, app).await?;

    return Ok(());
}
