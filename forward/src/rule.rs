use crate::utils::resolve_ip_mac;
use anyhow::Context as _;
use aya::maps::HashMap;
use forward_common::{ForwardKey, ForwardVal};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForwardRule {
    pub proto: u32,
    pub local_port: u32,
    pub forward_ip: Ipv4Addr,
    pub forward_port: u16,
    pub forward_mac: [u8; 6],
}

pub struct TimeoutsState {
    pub tcp_ns: AtomicU64,
    pub udp_ns: AtomicU64,
}

pub async fn add_forward_rule(
    ebpf: &Mutex<aya::Ebpf>,
    proto_str: &str,
    local_port: u32,
    forward_ip_str: &str,
    forward_port: u16,
) -> anyhow::Result<[u8; 6]> {
    let proto = match proto_str.to_lowercase().as_str() {
        "tcp" => 6u32,
        "udp" => 17u32,
        _ => anyhow::bail!("invalid protocol (must be tcp or udp)"),
    };

    let forward_ip = forward_ip_str
        .parse::<Ipv4Addr>()
        .context("invalid forward_ip")?;
    let forward_ip_be = u32::from(forward_ip).to_be();
    let forward_mac = resolve_ip_mac(forward_ip_str)
        .await
        .context("could not resolve MAC address for target IP")?;

    let mut ebpf_guard = ebpf.lock().await;
    let mut forward_map = HashMap::<_, ForwardKey, ForwardVal>::try_from(
        ebpf_guard
            .map_mut("FORWARD_MAP")
            .context("FORWARD_MAP not found")?,
    )?;

    let key = ForwardKey { proto, local_port };
    let val = ForwardVal {
        forward_ip: forward_ip_be,
        forward_port: forward_port.to_be(),
        forward_mac,
        pad: [0; 4],
    };

    forward_map
        .insert(key, val, 0)
        .context("failed to insert rule")?;

    return Ok(forward_mac);
}

pub async fn delete_forward_rule(
    ebpf: &Mutex<aya::Ebpf>,
    proto_str: &str,
    local_port: u32,
) -> anyhow::Result<()> {
    let proto = match proto_str.to_lowercase().as_str() {
        "tcp" => 6u32,
        "udp" => 17u32,
        _ => anyhow::bail!("invalid protocol (must be tcp or udp)"),
    };

    let mut ebpf_guard = ebpf.lock().await;
    let mut forward_map = HashMap::<_, ForwardKey, ForwardVal>::try_from(
        ebpf_guard
            .map_mut("FORWARD_MAP")
            .context("FORWARD_MAP not found")?,
    )?;

    let key = ForwardKey { proto, local_port };
    forward_map.remove(&key).context("failed to remove rule")?;

    return Ok(());
}

pub async fn list_forward_rules(ebpf: &Mutex<aya::Ebpf>) -> anyhow::Result<Vec<ForwardRule>> {
    let mut ebpf_guard = ebpf.lock().await;
    let forward_map = HashMap::<_, ForwardKey, ForwardVal>::try_from(
        ebpf_guard
            .map_mut("FORWARD_MAP")
            .context("FORWARD_MAP not found")?,
    )?;

    let mut rules = Vec::new();
    for item in forward_map.iter() {
        let (key, val) = item?;
        rules.push(ForwardRule {
            proto: key.proto,
            local_port: key.local_port,
            forward_ip: Ipv4Addr::from(u32::from_be(val.forward_ip)),
            forward_port: u16::from_be(val.forward_port),
            forward_mac: val.forward_mac,
        });
    }
    return Ok(rules);
}

pub fn set_timeout(timeouts: &TimeoutsState, proto_str: &str, seconds: u64) -> anyhow::Result<()> {
    let ns = seconds * 1_000_000_000;
    match proto_str.to_lowercase().as_str() {
        "tcp" => {
            timeouts.tcp_ns.store(ns, Ordering::Relaxed);
            Ok(())
        }
        "udp" => {
            timeouts.udp_ns.store(ns, Ordering::Relaxed);
            Ok(())
        }
        _ => anyhow::bail!("invalid protocol (must be tcp or udp)"),
    }
}

pub fn save_rules(rules_path: &str, rules: &[ForwardRule]) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(rules_path).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).context("failed to create directory for rules file")?;
        }
    }
    let file =
        std::fs::File::create(rules_path).context("failed to create rules file for writing")?;
    serde_json::to_writer_pretty(file, rules).context("failed to serialize rules to JSON")?;
    return Ok(());
}

pub async fn load_and_restore_rules(
    ebpf: &Mutex<aya::Ebpf>,
    rules_path: &str,
) -> anyhow::Result<()> {
    if !std::path::Path::new(rules_path).exists() {
        return Ok(());
    }

    let file = std::fs::File::open(rules_path).context("failed to open rules file for reading")?;
    let rules: Vec<ForwardRule> =
        serde_json::from_reader(file).context("failed to parse rules JSON")?;

    for rule in rules {
        let proto_str = if rule.proto == 6 { "tcp" } else { "udp" };
        log::info!(
            "Restoring persisted rule: {} {} -> {}:{}",
            proto_str,
            rule.local_port,
            rule.forward_ip,
            rule.forward_port
        );
        if let Err(e) = add_forward_rule(
            ebpf,
            proto_str,
            rule.local_port,
            &rule.forward_ip.to_string(),
            rule.forward_port,
        )
        .await
        {
            log::warn!(
                "Failed to restore rule {} {}: {:#}",
                proto_str,
                rule.local_port,
                e
            );
        }
    }

    return Ok(());
}
