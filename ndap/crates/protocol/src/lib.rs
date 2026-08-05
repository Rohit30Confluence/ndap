//! ndap-protocol — Phase 1 decoders + Phase 2 dissector framework.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------
// Phase 1: concrete decoded packet tree (fast path, no plugins needed)
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub enum L3 {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
    Arp { sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr, op: u16 },
    Other(u16),
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub total_len: u16,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
}

#[derive(Debug, Clone)]
pub enum L4 {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Other(u8),
    None,
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8, // bit0=FIN bit1=SYN bit2=RST bit3=PSH bit4=ACK bit5=URG
    pub window: u16,
}
impl TcpHeader {
    pub fn is_syn(&self) -> bool { self.flags & 0b0000_0010 != 0 }
    pub fn is_ack(&self) -> bool { self.flags & 0b0001_0000 != 0 }
    pub fn is_rst(&self) -> bool { self.flags & 0b0000_0100 != 0 }
    pub fn is_fin(&self) -> bool { self.flags & 0b0000_0001 != 0 }
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub eth: Option<EthernetFrame>,
    pub l3: Option<L3>,
    pub l4: L4,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum DecodeError {
    TooShort(&'static str),
}

pub fn decode_ethernet(data: &[u8]) -> Result<(EthernetFrame, &[u8]), DecodeError> {
    if data.len() < 14 {
        return Err(DecodeError::TooShort("ethernet"));
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    Ok((EthernetFrame { dst_mac, src_mac, ethertype }, &data[14..]))
}

pub fn decode_ipv4(data: &[u8]) -> Result<(Ipv4Header, &[u8]), DecodeError> {
    if data.len() < 20 {
        return Err(DecodeError::TooShort("ipv4"));
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return Err(DecodeError::TooShort("ipv4 options"));
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let ttl = data[8];
    let protocol = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    Ok((
        Ipv4Header { src, dst, protocol, ttl, total_len },
        &data[ihl..],
    ))
}

pub fn decode_ipv6(data: &[u8]) -> Result<(Ipv6Header, &[u8]), DecodeError> {
    if data.len() < 40 {
        return Err(DecodeError::TooShort("ipv6"));
    }
    let next_header = data[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());
    Ok((Ipv6Header { src, dst, next_header }, &data[40..]))
}

pub fn decode_tcp(data: &[u8]) -> Result<(TcpHeader, &[u8]), DecodeError> {
    if data.len() < 20 {
        return Err(DecodeError::TooShort("tcp"));
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) & 0x0F) as usize * 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    if data.len() < data_offset {
        return Err(DecodeError::TooShort("tcp options"));
    }
    Ok((
        TcpHeader { src_port, dst_port, seq, ack, flags, window },
        &data[data_offset..],
    ))
}

pub fn decode_udp(data: &[u8]) -> Result<(UdpHeader, &[u8]), DecodeError> {
    if data.len() < 8 {
        return Err(DecodeError::TooShort("udp"));
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    Ok((UdpHeader { src_port, dst_port, length }, &data[8..]))
}

/// Full decode pipeline: Ethernet -> IPv4/IPv6/ARP -> TCP/UDP.
pub fn decode_packet(raw: &[u8]) -> DecodedPacket {
    let mut result = DecodedPacket { eth: None, l3: None, l4: L4::None, payload: Vec::new() };

    let after_eth = match decode_ethernet(raw) {
        Ok((eth, rest)) => {
            let ethertype = eth.ethertype;
            result.eth = Some(eth);
            Some((ethertype, rest))
        }
        Err(_) => None,
    };

    let (ethertype, l3_data) = match after_eth {
        Some(v) => v,
        None => { result.payload = raw.to_vec(); return result; }
    };

    match ethertype {
        0x0800 => {
            if let Ok((ip4, rest)) = decode_ipv4(l3_data) {
                let proto = ip4.protocol;
                result.l3 = Some(L3::Ipv4(ip4));
                decode_l4(proto, rest, &mut result);
            }
        }
        0x86DD => {
            if let Ok((ip6, rest)) = decode_ipv6(l3_data) {
                let next = ip6.next_header;
                result.l3 = Some(L3::Ipv6(ip6));
                decode_l4(next, rest, &mut result);
            }
        }
        0x0806 => {
            if l3_data.len() >= 28 {
                let op = u16::from_be_bytes([l3_data[6], l3_data[7]]);
                let mut sender_mac = [0u8; 6];
                sender_mac.copy_from_slice(&l3_data[8..14]);
                let sender_ip = Ipv4Addr::new(l3_data[14], l3_data[15], l3_data[16], l3_data[17]);
                let target_ip = Ipv4Addr::new(l3_data[24], l3_data[25], l3_data[26], l3_data[27]);
                result.l3 = Some(L3::Arp { sender_mac, sender_ip, target_ip, op });
            }
        }
        other => {
            result.l3 = Some(L3::Other(other));
            result.payload = l3_data.to_vec();
        }
    }
    result
}

fn decode_l4(proto: u8, data: &[u8], out: &mut DecodedPacket) {
    match proto {
        6 => {
            if let Ok((tcp, rest)) = decode_tcp(data) {
                out.payload = rest.to_vec();
                out.l4 = L4::Tcp(tcp);
            }
        }
        17 => {
            if let Ok((udp, rest)) = decode_udp(data) {
                out.payload = rest.to_vec();
                out.l4 = L4::Udp(udp);
            }
        }
        other => {
            out.l4 = L4::Other(other);
            out.payload = data.to_vec();
        }
    }
}

// ---------------------------------------------------------------------
// Phase 2: dissector registry + plugin loader interface
// ---------------------------------------------------------------------

/// Implement this to add a new protocol dissector (equivalent to
/// Wireshark's per-protocol dissector). Register it under a key such as
/// a well-known TCP/UDP port or an ethertype.
pub trait Dissector: Send + Sync {
    fn name(&self) -> &str;
    /// Returns a human-readable field tree (name, value) — the protocol
    /// tree node for this layer. Real implementations should return a
    /// richer typed tree; kept simple here as the v0 interface.
    fn dissect(&self, payload: &[u8]) -> Vec<(String, String)>;
}

#[derive(Default)]
pub struct ProtocolRegistry {
    by_tcp_port: HashMap<u16, Box<dyn Dissector>>,
    by_udp_port: HashMap<u16, Box<dyn Dissector>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_tcp_port(&mut self, port: u16, dissector: Box<dyn Dissector>) {
        self.by_tcp_port.insert(port, dissector);
    }

    pub fn register_udp_port(&mut self, port: u16, dissector: Box<dyn Dissector>) {
        self.by_udp_port.insert(port, dissector);
    }

    pub fn dissect_tcp(&self, port: u16, payload: &[u8]) -> Option<Vec<(String, String)>> {
        self.by_tcp_port.get(&port).map(|d| d.dissect(payload))
    }

    pub fn dissect_udp(&self, port: u16, payload: &[u8]) -> Option<Vec<(String, String)>> {
        self.by_udp_port.get(&port).map(|d| d.dissect(payload))
    }
}

/// Plugin loader interface. v0 is an in-process Rust trait; a later
/// version can back this with dynamically loaded `.so`/`.dll` plugins
/// or a Python bridge (PyO3) for the "Python for extensibility" goal
/// in the original proposal, without changing `ProtocolRegistry`.
pub trait PluginLoader {
    fn load_plugins(&self, dir: &str, registry: &mut ProtocolRegistry) -> Result<usize, String>;
}

pub struct NoopPluginLoader;
impl PluginLoader for NoopPluginLoader {
    fn load_plugins(&self, _dir: &str, _registry: &mut ProtocolRegistry) -> Result<usize, String> {
        Ok(0) // TODO: real plugin discovery/loading
    }
}
