//! ndap-flow — Phase 3: Flow Engine (conversations, TCP stream reassembly).

use ndap_protocol::{DecodedPacket, L3, L4};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // 6=TCP, 17=UDP
}

impl FiveTuple {
    /// Canonical (direction-independent) key so both directions of a
    /// conversation map to the same bucket.
    pub fn canonical(&self) -> FiveTuple {
        let (a_ip, a_port, b_ip, b_port) = (self.src_ip, self.src_port, self.dst_ip, self.dst_port);
        if (a_ip, a_port) <= (b_ip, b_port) {
            self.clone()
        } else {
            FiveTuple {
                src_ip: b_ip,
                dst_ip: a_ip,
                src_port: b_port,
                dst_port: a_port,
                protocol: self.protocol,
            }
        }
    }
}

pub fn five_tuple_of(pkt: &DecodedPacket) -> Option<FiveTuple> {
    let (src_ip, dst_ip, protocol_hint) = match pkt.l3.as_ref()? {
        L3::Ipv4(h) => (IpAddr::V4(h.src), IpAddr::V4(h.dst), h.protocol),
        L3::Ipv6(h) => (IpAddr::V6(h.src), IpAddr::V6(h.dst), h.next_header),
        _ => return None,
    };
    let (src_port, dst_port, protocol) = match &pkt.l4 {
        L4::Tcp(t) => (t.src_port, t.dst_port, 6u8),
        L4::Udp(u) => (u.src_port, u.dst_port, 17u8),
        _ => (0, 0, protocol_hint),
    };
    Some(FiveTuple { src_ip, dst_ip, src_port, dst_port, protocol })
}

#[derive(Debug, Default)]
pub struct ConversationStats {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: Option<(u32, u32)>, // (ts_sec, ts_usec)
    pub last_seen: Option<(u32, u32)>,
}

/// Minimal per-direction TCP reassembly buffer keyed by expected seq.
/// Real implementation needs SACK/out-of-order handling — this is the
/// v0 skeleton with the interface Phase 4/5 consumers can build against.
#[derive(Debug, Default)]
pub struct TcpStream {
    pub next_seq: Option<u32>,
    pub reassembled: Vec<u8>,
    pub out_of_order: HashMap<u32, Vec<u8>>,
}

impl TcpStream {
    pub fn push(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        match self.next_seq {
            None => {
                self.next_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.reassembled.extend_from_slice(payload);
            }
            Some(expected) if expected == seq => {
                self.reassembled.extend_from_slice(payload);
                let mut next = seq.wrapping_add(payload.len() as u32);
                // drain any buffered segments that now become contiguous
                while let Some(buf) = self.out_of_order.remove(&next) {
                    let len = buf.len() as u32;
                    self.reassembled.extend_from_slice(&buf);
                    next = next.wrapping_add(len);
                }
                self.next_seq = Some(next);
            }
            Some(_) => {
                self.out_of_order.insert(seq, payload.to_vec());
            }
        }
    }
}

pub struct ConversationTracker {
    pub conversations: HashMap<FiveTuple, ConversationStats>,
    pub tcp_streams: HashMap<FiveTuple, (TcpStream, TcpStream)>, // (a->b, b->a)
}

impl ConversationTracker {
    pub fn new() -> Self {
        Self { conversations: HashMap::new(), tcp_streams: HashMap::new() }
    }

    pub fn record(&mut self, pkt: &DecodedPacket, ts_sec: u32, ts_usec: u32) {
        let Some(tuple) = five_tuple_of(pkt) else { return };
        let key = tuple.canonical();

        let stats = self.conversations.entry(key.clone()).or_default();
        stats.packets += 1;
        stats.bytes += pkt.payload.len() as u64;
        if stats.first_seen.is_none() {
            stats.first_seen = Some((ts_sec, ts_usec));
        }
        stats.last_seen = Some((ts_sec, ts_usec));

        if let L4::Tcp(tcp) = &pkt.l4 {
            let entry = self.tcp_streams.entry(key.clone()).or_default();
            let forward = tuple.src_port == key.src_port && tuple.src_ip == key.src_ip;
            let stream = if forward { &mut entry.0 } else { &mut entry.1 };
            stream.push(tcp.seq, &pkt.payload);
        }
    }
}

impl Default for ConversationTracker {
    fn default() -> Self {
        Self::new()
    }
}
