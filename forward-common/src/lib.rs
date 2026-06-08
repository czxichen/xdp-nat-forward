#![no_std]

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ForwardKey {
    pub proto: u32,       // 6 for TCP, 17 for UDP
    pub local_port: u32,  // Local port (host byte order)
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ForwardVal {
    pub forward_ip: u32,    // Target IP (network byte order)
    pub forward_port: u16,  // Target Port (network byte order)
    pub forward_mac: [u8; 6],
    pub pad: [u8; 4],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SessionKey {
    pub client_ip: u32,    // network byte order
    pub target_ip: u32,    // network byte order
    pub client_port: u16,  // network byte order
    pub target_port: u16,  // network byte order
    pub proto: u8,
    pub pad: [u8; 3],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SessionVal {
    pub nat_port: u16,        // network byte order
    pub client_mac: [u8; 6],
    pub last_seen: u64,       // uptime nanoseconds
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct RevSessionKey {
    pub target_ip: u32,   // network byte order
    pub nat_port: u16,    // network byte order
    pub target_port: u16, // network byte order
    pub proto: u8,
    pub pad: [u8; 3],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct RevSessionVal {
    pub client_ip: u32,    // network byte order
    pub client_port: u16,  // network byte order
    pub local_port: u16,   // original local port (network byte order)
    pub client_mac: [u8; 6],
    pub pad: [u8; 2],
    pub last_seen: u64,    // uptime nanoseconds
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ForwardKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ForwardVal {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionVal {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RevSessionKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RevSessionVal {}
