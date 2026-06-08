#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use forward_common::{
    ForwardKey, ForwardVal, RevSessionKey, RevSessionVal, SessionKey, SessionVal,
};

#[map]
static FORWARD_MAP: HashMap<ForwardKey, ForwardVal> = HashMap::with_max_entries(1024, 0);

#[map]
static SESSION_MAP: HashMap<SessionKey, SessionVal> = HashMap::with_max_entries(16384, 0);

#[map]
static REVERSE_SESSION_MAP: HashMap<RevSessionKey, RevSessionVal> =
    HashMap::with_max_entries(16384, 0);

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct EthHdr {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct IpHdr {
    ver_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src_ip: u32,
    dst_ip: u32,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    len: u16,
    check: u16,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    data_off_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
fn csum_fold(mut sum: u32) -> u16 {
    for _ in 0..4 {
        if (sum >> 16) == 0 {
            break;
        }
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[inline(always)]
fn update_csum_16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum = (!old_csum) as u32;
    sum += (!old_val) as u32;
    sum += new_val as u32;
    csum_fold(sum)
}

#[inline(always)]
fn update_csum_32(old_csum: u16, old_val: u32, new_val: u32) -> u16 {
    let old_h = (old_val >> 16) as u16;
    let old_l = (old_val & 0xFFFF) as u16;
    let new_h = (new_val >> 16) as u16;
    let new_l = (new_val & 0xFFFF) as u16;
    let mut csum = update_csum_16(old_csum, old_h, new_h);
    csum = update_csum_16(csum, old_l, new_l);
    csum
}

#[inline(always)]
fn allocate_nat_port(
    client_ip: u32,
    target_ip: u32,
    client_port: u16,
    target_port: u16,
    proto: u8,
) -> Option<u16> {
    let hash = client_ip ^ target_ip ^ (client_port as u32) ^ (target_port as u32);
    for i in 0..5 {
        let port = 32768 + ((hash + i) % 16384) as u16;
        let rev_key = RevSessionKey {
            target_ip,
            nat_port: u16::to_be(port),
            target_port,
            proto,
            pad: [0; 3],
        };
        if unsafe { REVERSE_SESSION_MAP.get(&rev_key) }.is_none() {
            return Some(port);
        }
    }
    None
}

#[xdp]
pub fn forward(ctx: XdpContext) -> u32 {
    match try_forward(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_forward(ctx: XdpContext) -> Result<u32, ()> {
    let eth = unsafe { ptr_at_mut::<EthHdr>(&ctx, 0)? };
    if u16::from_be(unsafe { (*eth).ether_type }) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = core::mem::size_of::<EthHdr>();
    let ip = unsafe { ptr_at_mut::<IpHdr>(&ctx, ip_offset)? };
    let ip_len = (unsafe { (*ip).ver_ihl } & 0x0F) as usize * 4;
    if ip_len < 20 || ip_len > 60 {
        return Ok(xdp_action::XDP_PASS);
    }

    let l4_offset = ip_offset + ip_len;
    let proto = unsafe { (*ip).proto };
    if proto != 6 && proto != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = unsafe { (*ip).src_ip };
    let dst_ip = unsafe { (*ip).dst_ip };

    if proto == 6 {
        // TCP
        let tcp = unsafe { ptr_at_mut::<TcpHdr>(&ctx, l4_offset)? };
        let src_port = unsafe { (*tcp).src_port };
        let dst_port = unsafe { (*tcp).dst_port };

        // 1. Check Forward Map (Client -> NAT -> Target)
        let f_key = ForwardKey {
            proto: proto as u32,
            local_port: u16::from_be(dst_port) as u32,
        };

        if let Some(f_val) = unsafe { FORWARD_MAP.get(&f_key) } {
            let target_ip = f_val.forward_ip;
            let target_port = f_val.forward_port;
            let target_mac = f_val.forward_mac;

            let s_key = SessionKey {
                client_ip: src_ip,
                target_ip,
                client_port: src_port,
                target_port,
                proto,
                pad: [0; 3],
            };

            let time_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
            let nat_port;

            if let Some(s_val_ptr) = SESSION_MAP.get_ptr_mut(&s_key) {
                nat_port = unsafe { (*s_val_ptr).nat_port };
                unsafe {
                    (*s_val_ptr).last_seen = time_ns;
                }

                let rev_key = RevSessionKey {
                    target_ip,
                    nat_port,
                    target_port,
                    proto,
                    pad: [0; 3],
                };
                if let Some(rev_val_ptr) = REVERSE_SESSION_MAP.get_ptr_mut(&rev_key) {
                    unsafe {
                        (*rev_val_ptr).last_seen = time_ns;
                    }
                }
            } else {
                if let Some(allocated_port) =
                    allocate_nat_port(src_ip, target_ip, src_port, target_port, proto)
                {
                    nat_port = u16::to_be(allocated_port);
                    let client_mac = unsafe { (*eth).src_mac };

                    let s_val = SessionVal {
                        nat_port,
                        client_mac,
                        last_seen: time_ns,
                    };
                    let _ = SESSION_MAP.insert(&s_key, &s_val, 0);

                    let rev_key = RevSessionKey {
                        target_ip,
                        nat_port,
                        target_port,
                        proto,
                        pad: [0; 3],
                    };
                    let rev_val = RevSessionVal {
                        client_ip: src_ip,
                        client_port: src_port,
                        local_port: dst_port,
                        client_mac,
                        pad: [0; 2],
                        last_seen: time_ns,
                    };
                    let _ = REVERSE_SESSION_MAP.insert(&rev_key, &rev_val, 0);
                } else {
                    return Ok(xdp_action::XDP_ABORTED);
                }
            }

            // Rewrite IP/TCP and Ethernet
            let old_src_ip = src_ip;
            let old_dst_ip = dst_ip;
            let new_src_ip = dst_ip; // NAT IP (incoming Dst IP)
            let new_dst_ip = target_ip;

            unsafe {
                (*eth).src_mac = (*eth).dst_mac;
                (*eth).dst_mac = target_mac;
                (*ip).src_ip = new_src_ip;
                (*ip).dst_ip = new_dst_ip;
            }

            let mut ip_csum = u16::from_be(unsafe { (*ip).check });
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
            unsafe {
                (*ip).check = ip_csum.to_be();
            }

            let old_src_port = src_port;
            let old_dst_port = dst_port;
            let new_src_port = nat_port;
            let new_dst_port = target_port;

            unsafe {
                (*tcp).src_port = new_src_port;
                (*tcp).dst_port = new_dst_port;
            }

            let mut tcp_csum = u16::from_be(unsafe { (*tcp).check });
            tcp_csum = update_csum_32(tcp_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
            tcp_csum = update_csum_32(tcp_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
            tcp_csum = update_csum_16(
                tcp_csum,
                u16::from_be(old_src_port),
                u16::from_be(new_src_port),
            );
            tcp_csum = update_csum_16(
                tcp_csum,
                u16::from_be(old_dst_port),
                u16::from_be(new_dst_port),
            );
            unsafe {
                (*tcp).check = tcp_csum.to_be();
            }

            info!(&ctx, "TCP FW: Client->Target NAT'd");
            return Ok(xdp_action::XDP_TX);
        }

        // 2. Check Reverse Session Map (Target -> NAT -> Client)
        let rev_key = RevSessionKey {
            target_ip: src_ip,
            nat_port: dst_port,
            target_port: src_port,
            proto,
            pad: [0; 3],
        };

        if let Some(rev_val) = unsafe { REVERSE_SESSION_MAP.get(&rev_key) } {
            let client_ip = rev_val.client_ip;
            let client_port = rev_val.client_port;
            let local_port = rev_val.local_port;
            let client_mac = rev_val.client_mac;
            let time_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

            if let Some(rev_val_ptr) = REVERSE_SESSION_MAP.get_ptr_mut(&rev_key) {
                unsafe {
                    (*rev_val_ptr).last_seen = time_ns;
                }
            }

            let s_key = SessionKey {
                client_ip,
                target_ip: src_ip,
                client_port,
                target_port: src_port,
                proto,
                pad: [0; 3],
            };
            if let Some(s_val_ptr) = SESSION_MAP.get_ptr_mut(&s_key) {
                unsafe {
                    (*s_val_ptr).last_seen = time_ns;
                }
            }

            // Rewrite IP/TCP and Ethernet
            let old_src_ip = src_ip;
            let old_dst_ip = dst_ip;
            let new_src_ip = dst_ip; // NAT IP (incoming Dst IP)
            let new_dst_ip = client_ip;

            unsafe {
                (*eth).src_mac = (*eth).dst_mac;
                (*eth).dst_mac = client_mac;
                (*ip).src_ip = new_src_ip;
                (*ip).dst_ip = new_dst_ip;
            }

            let mut ip_csum = u16::from_be(unsafe { (*ip).check });
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
            unsafe {
                (*ip).check = ip_csum.to_be();
            }

            let old_src_port = src_port;
            let old_dst_port = dst_port;
            let new_src_port = local_port;
            let new_dst_port = client_port;

            unsafe {
                (*tcp).src_port = new_src_port;
                (*tcp).dst_port = new_dst_port;
            }

            let mut tcp_csum = u16::from_be(unsafe { (*tcp).check });
            tcp_csum = update_csum_32(tcp_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
            tcp_csum = update_csum_32(tcp_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
            tcp_csum = update_csum_16(
                tcp_csum,
                u16::from_be(old_src_port),
                u16::from_be(new_src_port),
            );
            tcp_csum = update_csum_16(
                tcp_csum,
                u16::from_be(old_dst_port),
                u16::from_be(new_dst_port),
            );
            unsafe {
                (*tcp).check = tcp_csum.to_be();
            }

            info!(&ctx, "TCP REV: Target->Client NAT'd");
            return Ok(xdp_action::XDP_TX);
        }
    } else if proto == 17 {
        // UDP
        let udp = unsafe { ptr_at_mut::<UdpHdr>(&ctx, l4_offset)? };
        let src_port = unsafe { (*udp).src_port };
        let dst_port = unsafe { (*udp).dst_port };

        // 1. Check Forward Map (Client -> NAT -> Target)
        let f_key = ForwardKey {
            proto: proto as u32,
            local_port: u16::from_be(dst_port) as u32,
        };

        if let Some(f_val) = unsafe { FORWARD_MAP.get(&f_key) } {
            let target_ip = f_val.forward_ip;
            let target_port = f_val.forward_port;
            let target_mac = f_val.forward_mac;

            let s_key = SessionKey {
                client_ip: src_ip,
                target_ip,
                client_port: src_port,
                target_port,
                proto,
                pad: [0; 3],
            };

            let time_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
            let nat_port;

            if let Some(s_val_ptr) = SESSION_MAP.get_ptr_mut(&s_key) {
                nat_port = unsafe { (*s_val_ptr).nat_port };
                unsafe {
                    (*s_val_ptr).last_seen = time_ns;
                }

                let rev_key = RevSessionKey {
                    target_ip,
                    nat_port,
                    target_port,
                    proto,
                    pad: [0; 3],
                };
                if let Some(rev_val_ptr) = REVERSE_SESSION_MAP.get_ptr_mut(&rev_key) {
                    unsafe {
                        (*rev_val_ptr).last_seen = time_ns;
                    }
                }
            } else {
                if let Some(allocated_port) =
                    allocate_nat_port(src_ip, target_ip, src_port, target_port, proto)
                {
                    nat_port = u16::to_be(allocated_port);
                    let client_mac = unsafe { (*eth).src_mac };

                    let s_val = SessionVal {
                        nat_port,
                        client_mac,
                        last_seen: time_ns,
                    };
                    let _ = SESSION_MAP.insert(&s_key, &s_val, 0);

                    let rev_key = RevSessionKey {
                        target_ip,
                        nat_port,
                        target_port,
                        proto,
                        pad: [0; 3],
                    };
                    let rev_val = RevSessionVal {
                        client_ip: src_ip,
                        client_port: src_port,
                        local_port: dst_port,
                        client_mac,
                        pad: [0; 2],
                        last_seen: time_ns,
                    };
                    let _ = REVERSE_SESSION_MAP.insert(&rev_key, &rev_val, 0);
                } else {
                    return Ok(xdp_action::XDP_ABORTED);
                }
            }

            // Rewrite IP/UDP and Ethernet
            let old_src_ip = src_ip;
            let old_dst_ip = dst_ip;
            let new_src_ip = dst_ip; // NAT IP
            let new_dst_ip = target_ip;

            unsafe {
                (*eth).src_mac = (*eth).dst_mac;
                (*eth).dst_mac = target_mac;
                (*ip).src_ip = new_src_ip;
                (*ip).dst_ip = new_dst_ip;
            }

            let mut ip_csum = u16::from_be(unsafe { (*ip).check });
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
            unsafe {
                (*ip).check = ip_csum.to_be();
            }

            let old_src_port = src_port;
            let old_dst_port = dst_port;
            let new_src_port = nat_port;
            let new_dst_port = target_port;

            unsafe {
                (*udp).src_port = new_src_port;
                (*udp).dst_port = new_dst_port;
            }

            let mut udp_csum = u16::from_be(unsafe { (*udp).check });
            if udp_csum != 0 {
                udp_csum =
                    update_csum_32(udp_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
                udp_csum =
                    update_csum_32(udp_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
                udp_csum = update_csum_16(
                    udp_csum,
                    u16::from_be(old_src_port),
                    u16::from_be(new_src_port),
                );
                udp_csum = update_csum_16(
                    udp_csum,
                    u16::from_be(old_dst_port),
                    u16::from_be(new_dst_port),
                );
                if udp_csum == 0 {
                    udp_csum = 0xFFFF;
                }
                unsafe {
                    (*udp).check = udp_csum.to_be();
                }
            }

            info!(&ctx, "UDP FW: Client->Target NAT'd");
            return Ok(xdp_action::XDP_TX);
        }

        // 2. Check Reverse Session Map (Target -> NAT -> Client)
        let rev_key = RevSessionKey {
            target_ip: src_ip,
            nat_port: dst_port,
            target_port: src_port,
            proto,
            pad: [0; 3],
        };

        if let Some(rev_val) = unsafe { REVERSE_SESSION_MAP.get(&rev_key) } {
            let client_ip = rev_val.client_ip;
            let client_port = rev_val.client_port;
            let local_port = rev_val.local_port;
            let client_mac = rev_val.client_mac;
            let time_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

            if let Some(rev_val_ptr) = REVERSE_SESSION_MAP.get_ptr_mut(&rev_key) {
                unsafe {
                    (*rev_val_ptr).last_seen = time_ns;
                }
            }

            let s_key = SessionKey {
                client_ip,
                target_ip: src_ip,
                client_port,
                target_port: src_port,
                proto,
                pad: [0; 3],
            };
            if let Some(s_val_ptr) = SESSION_MAP.get_ptr_mut(&s_key) {
                unsafe {
                    (*s_val_ptr).last_seen = time_ns;
                }
            }

            // Rewrite IP/UDP and Ethernet
            let old_src_ip = src_ip;
            let old_dst_ip = dst_ip;
            let new_src_ip = dst_ip; // NAT IP
            let new_dst_ip = client_ip;

            unsafe {
                (*eth).src_mac = (*eth).dst_mac;
                (*eth).dst_mac = client_mac;
                (*ip).src_ip = new_src_ip;
                (*ip).dst_ip = new_dst_ip;
            }

            let mut ip_csum = u16::from_be(unsafe { (*ip).check });
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
            ip_csum = update_csum_32(ip_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
            unsafe {
                (*ip).check = ip_csum.to_be();
            }

            let old_src_port = src_port;
            let old_dst_port = dst_port;
            let new_src_port = local_port;
            let new_dst_port = client_port;

            unsafe {
                (*udp).src_port = new_src_port;
                (*udp).dst_port = new_dst_port;
            }

            let mut udp_csum = u16::from_be(unsafe { (*udp).check });
            if udp_csum != 0 {
                udp_csum =
                    update_csum_32(udp_csum, u32::from_be(old_src_ip), u32::from_be(new_src_ip));
                udp_csum =
                    update_csum_32(udp_csum, u32::from_be(old_dst_ip), u32::from_be(new_dst_ip));
                udp_csum = update_csum_16(
                    udp_csum,
                    u16::from_be(old_src_port),
                    u16::from_be(new_src_port),
                );
                udp_csum = update_csum_16(
                    udp_csum,
                    u16::from_be(old_dst_port),
                    u16::from_be(new_dst_port),
                );
                if udp_csum == 0 {
                    udp_csum = 0xFFFF;
                }
                unsafe {
                    (*udp).check = udp_csum.to_be();
                }
            }

            info!(&ctx, "UDP REV: Target->Client NAT'd");
            return Ok(xdp_action::XDP_TX);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
