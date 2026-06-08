use log::warn;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn get_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

pub fn parse_mac(mac_str: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for i in 0..6 {
        mac[i] = u8::from_str_radix(parts[i], 16).ok()?;
    }
    Some(mac)
}

pub fn find_mac_in_arp(ip_str: &str) -> Option<[u8; 6]> {
    let file = File::open("/proc/net/arp").ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line = line.ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == ip_str {
            let mac_str = parts[3];
            if mac_str != "00:00:00:00:00:00" {
                return parse_mac(mac_str);
            }
        }
    }
    None
}

pub async fn trigger_arp(ip_str: &str) {
    let addr = format!("{}:55555", ip_str);
    if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        let _ = socket.send_to(b"ping", &addr).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

pub fn get_gateway_ip() -> Option<String> {
    let file = File::open("/proc/net/route").ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line = line.ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "00000000" {
            let gw_hex = parts[2];
            if let Ok(gw_val) = u32::from_str_radix(gw_hex, 16) {
                if gw_val == 0 {
                    continue;
                }
                let ip_bytes = gw_val.to_ne_bytes();
                return Some(format!(
                    "{}.{}.{}.{}",
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                ));
            }
        }
    }
    None
}

pub async fn resolve_ip_mac(ip_str: &str) -> Option<[u8; 6]> {
    if let Some(mac) = find_mac_in_arp(ip_str) {
        return Some(mac);
    }
    trigger_arp(ip_str).await;
    if let Some(mac) = find_mac_in_arp(ip_str) {
        return Some(mac);
    }
    if let Some(gw_ip) = get_gateway_ip() {
        if let Some(mac) = find_mac_in_arp(&gw_ip) {
            return Some(mac);
        }
        trigger_arp(&gw_ip).await;
        if let Some(mac) = find_mac_in_arp(&gw_ip) {
            return Some(mac);
        }
    }
    None
}

pub fn setup_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {ret}");
    }
}
