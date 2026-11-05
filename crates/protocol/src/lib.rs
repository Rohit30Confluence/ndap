//! ndap-protocol — Phase 1 decoders + Phase 2 dissector framework.

pub mod dissector;
pub mod dns;
pub mod http;
pub mod icmp;

pub use dissector::{Dissector, DissectionResult, NoopPluginLoader, PluginLoader, ProtocolRegistry};
pub use dns::{dns_opcode_name, dns_rcode_name, dns_type_name, parse_dns, DnsDissector, DnsError, DnsHeader, DnsMessage, DnsQuestion, DnsRecord};
pub use http::{is_http_payload, parse_http, HttpDissector, HttpError, HttpHeader, HttpMessage, HttpRequest, HttpResponse};
pub use icmp::{decode_icmp, IcmpHeader};

use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------
// Phase 1: concrete decoded packet tree (fast path, zero external deps)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3 {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
    Arp { sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr, op: u16 },
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub total_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4 {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Other(u8),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacket {
    pub eth: Option<EthernetFrame>,
    pub l3: Option<L3>,
    pub l4: L4,
    pub payload: Vec<u8>,
}

impl DecodedPacket {
    /// Dissects the packet using the provided ProtocolRegistry.
    pub fn dissect(&self, registry: &ProtocolRegistry) -> Option<DissectionResult> {
        registry.dissect_packet(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
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

/// Full decode pipeline: Ethernet -> IPv4/IPv6/ARP -> TCP/UDP/ICMP.
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
        1 | 58 => {
            if let Ok((icmp, rest)) = decode_icmp(data) {
                out.payload = rest.to_vec();
                out.l4 = L4::Icmp(icmp);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_dns_packet_dissection() {
        // Construct full packet: Ethernet + IPv4 + UDP + DNS query
        let mut pkt = Vec::new();
        // Ethernet: Dst MAC, Src MAC, EtherType 0x0800
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        // IPv4: Version/IHL 0x45, DSCP/ECN 0, Total Len 57, ID 1, Flags/Frag 0, TTL 64, Proto 17 (UDP), Checksum 0
        // Src: 192.168.1.100, Dst: 8.8.8.8
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x39, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
            192, 168, 1, 100, 8, 8, 8, 8,
        ]);

        // UDP: Src port 53535, Dst port 53, Len 37, Checksum 0
        pkt.extend_from_slice(&[
            0xd1, 0x1f, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00,
        ]);

        // DNS Query for google.com
        pkt.extend_from_slice(&[
            0xaa, 0xbb, // ID
            0x01, 0x00, // Standard query, RD=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 6google3com0
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01, // A, IN
        ]);

        let decoded = decode_packet(&pkt);
        assert!(decoded.eth.is_some());
        assert!(matches!(decoded.l3, Some(L3::Ipv4(_))));
        assert!(matches!(decoded.l4, L4::Udp(_)));

        let reg = ProtocolRegistry::with_builtin_dissectors();
        let dissection = decoded.dissect(&reg).expect("should dissect DNS");
        assert_eq!(dissection.protocol, "dns");
        assert_eq!(dissection.get_field("dns.qry.name"), Some("google.com"));
        assert_eq!(dissection.get_field("dns.qry.type"), Some("A"));
    }

    #[test]
    fn test_full_http_packet_dissection() {
        // Construct full packet: Ethernet + IPv4 + TCP + HTTP Request
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        // IPv4 (Proto 6 = TCP)
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x60, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
            10, 0, 0, 5, 10, 0, 0, 1,
        ]);

        // TCP: Src port 49152, Dst port 80, Seq 1, Ack 1, Offset 5 (20 bytes), Flags PSH|ACK (0x18), Win 65535, Chk 0, Urg 0
        pkt.extend_from_slice(&[
            0xc0, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x50, 0x18, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        ]);

        // HTTP GET
        pkt.extend_from_slice(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");

        let decoded = decode_packet(&pkt);
        assert!(matches!(decoded.l4, L4::Tcp(_)));

        let reg = ProtocolRegistry::with_builtin_dissectors();
        let dissection = decoded.dissect(&reg).expect("should dissect HTTP");
        assert_eq!(dissection.protocol, "http");
        assert_eq!(dissection.get_field("http.method"), Some("GET"));
        assert_eq!(dissection.get_field("http.request_uri"), Some("/index.html"));
        assert_eq!(dissection.get_field("http.host"), Some("example.com"));
    }

    #[test]
    fn test_full_icmp_packet_dissection() {
        // Construct full packet: Ethernet + IPv4 + ICMP Echo Request
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        // IPv4 (Proto 1 = ICMP)
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2,
        ]);

        // ICMP: Echo Request (8), Code 0, Checksum 0, ID 0x4321, Seq 0x0002
        pkt.extend_from_slice(&[
            0x08, 0x00, 0x00, 0x00, 0x43, 0x21, 0x00, 0x02,
            0x68, 0x65, 0x6c, 0x6c, 0x6f, // "hello"
        ]);

        let decoded = decode_packet(&pkt);
        match &decoded.l4 {
            L4::Icmp(icmp) => {
                assert!(icmp.is_echo_request());
                assert_eq!(icmp.echo_id(), 0x4321);
                assert_eq!(icmp.echo_seq(), 2);
            }
            _ => panic!("expected ICMP L4"),
        }

        let reg = ProtocolRegistry::with_builtin_dissectors();
        let dissection = decoded.dissect(&reg).expect("should dissect ICMP");
        assert_eq!(dissection.protocol, "icmp");
        assert_eq!(dissection.get_field("icmp.type_name"), Some("Echo Request"));
        assert_eq!(dissection.get_field("icmp.id"), Some("17185")); // 0x4321 = 17185
        assert_eq!(dissection.get_field("icmp.seq"), Some("2"));
    }
}
