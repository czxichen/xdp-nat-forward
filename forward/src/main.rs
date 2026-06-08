mod cmd;
mod http;
mod rule;
mod utils;

use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpMode};
use clap::{Parser, Subcommand};
use forward_common::{RevSessionKey, RevSessionVal, SessionKey, SessionVal};
use log::{info, warn};
pub use rule::{
    ForwardRule, TimeoutsState, add_forward_rule, delete_forward_rule, list_forward_rules,
    set_timeout,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::signal;
use tokio::sync::Mutex;
pub use utils::{get_monotonic_ns, setup_memlock_limit};

#[derive(Debug, Parser)]
#[clap(name = "forward", about = "XDP NAT Forwarder")]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long, default_value = "/tmp/forward.sock")]
    socket: String,

    #[clap(short, long, default_value = "127.0.0.1:8080")]
    addr: String,

    #[clap(long, default_value = "forward-secret-key")]
    secret: String,

    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Add {
        proto: String,
        local_port: u16,
        forward_ip: String,
        forward_port: u16,
    },
    Del {
        proto: String,
        local_port: u16,
    },
    List,
    Timeout {
        proto: String,
        seconds: u64,
    },
}

fn load_ebpf() -> anyhow::Result<aya::Ebpf> {
    let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/forward"
    )))?;
    return Ok(ebpf);
}

fn init_ebpf_logger(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    return Ok(());
}

fn attach_xdp(ebpf: &mut aya::Ebpf, iface: &str) -> anyhow::Result<()> {
    let program: &mut Xdp = ebpf.program_mut("forward").unwrap().try_into()?;
    program.load()?;
    if let Err(e) = program.attach(iface, XdpMode::default()) {
        warn!("failed to attach XDP program with default mode: {e:#}. Retrying in SKB (generic) mode...");
        program.attach(iface, XdpMode::Skb)
            .context("failed to attach XDP program in SKB mode")?;
    }
    return Ok(());
}

fn spawn_session_cleanup_task(ebpf: Arc<Mutex<aya::Ebpf>>, timeouts: Arc<TimeoutsState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            let current_time_ns = get_monotonic_ns();
            let tcp_timeout = timeouts.tcp_ns.load(Ordering::Relaxed);
            let udp_timeout = timeouts.udp_ns.load(Ordering::Relaxed);

            let mut to_delete = Vec::new();
            {
                let mut ebpf_guard = ebpf.lock().await;
                if let Ok(session_map) = HashMap::<_, SessionKey, SessionVal>::try_from(
                    ebpf_guard.map_mut("SESSION_MAP").unwrap(),
                ) {
                    for item in session_map.iter() {
                        if let Ok((key, val)) = item {
                            let elapsed = current_time_ns.saturating_sub(val.last_seen);
                            let timeout = if key.proto == 6 {
                                tcp_timeout
                            } else {
                                udp_timeout
                            };
                            if elapsed > timeout {
                                to_delete.push((key, val));
                            }
                        }
                    }
                }

                if !to_delete.is_empty() {
                    if let Ok(mut session_map) = HashMap::<_, SessionKey, SessionVal>::try_from(
                        ebpf_guard.map_mut("SESSION_MAP").unwrap(),
                    ) {
                        for (key, _) in &to_delete {
                            let _ = session_map.remove(key);
                        }
                    }
                    if let Ok(mut rev_session_map) =
                        HashMap::<_, RevSessionKey, RevSessionVal>::try_from(
                            ebpf_guard.map_mut("REVERSE_SESSION_MAP").unwrap(),
                        )
                    {
                        for (key, val) in &to_delete {
                            let rev_key = RevSessionKey {
                                target_ip: key.target_ip,
                                nat_port: val.nat_port,
                                target_port: key.target_port,
                                proto: key.proto,
                                pad: [0; 3],
                            };
                            let _ = rev_session_map.remove(&rev_key);
                        }
                    }
                    info!("Cleaned up {} expired sessions", to_delete.len());
                }
            }
        }
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    if let Some(command) = opt.command {
        return cmd::run_client(&opt.socket, command).await;
    }

    // Daemon Mode
    setup_memlock_limit();

    let mut ebpf = load_ebpf()?;
    init_ebpf_logger(&mut ebpf)?;

    let Opt {
        iface,
        socket,
        addr,
        secret,
        ..
    } = opt;

    attach_xdp(&mut ebpf, &iface)?;

    let timeouts = Arc::new(TimeoutsState {
        udp_ns: AtomicU64::new(60 * 1_000_000_000),
        tcp_ns: AtomicU64::new(300 * 1_000_000_000),
    });

    let ebpf = Arc::new(Mutex::new(ebpf));

    spawn_session_cleanup_task(Arc::clone(&ebpf), Arc::clone(&timeouts));

    let mut socket_task =
        cmd::spawn_uds_server(&socket, Arc::clone(&ebpf), Arc::clone(&timeouts)).await?;

    let mut http_task =
        http::spawn_http_server(&addr, Arc::clone(&ebpf), Arc::clone(&timeouts), secret).await?;

    info!("Waiting for Ctrl-C or server exit...");

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl-C, exiting...");
        }
        res = &mut socket_task => {
            warn!("Socket server task exited: {:?}", res);
        }
        res = &mut http_task => {
            warn!("HTTP server task exited: {:?}", res);
        }
    }

    http_task.abort();
    socket_task.abort();
    let _ = std::fs::remove_file(&socket);
    info!("Exiting...");

    return Ok(());
}
