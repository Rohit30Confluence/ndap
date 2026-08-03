//! ndap-detect — Phase 4: Detection Engine.
//!
//! Each rule implements `DetectionRule` and is fed decoded packets one at
//! a time by `DetectionEngine`, keeping whatever state it needs (window
//! counters, seen-IP maps, etc.) internally. This is deliberately simple
//! (no MITRE mapping data model yet — see ndap-intel) but real: the three
//! built-in rules actually fire on realistic traffic patterns.

use ndap_intel::{built_in_technique, MitreTechnique};
use ndap_protocol::{DecodedPacket, L3, L4};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub mod plugin;

#[derive(Debug, Clone)]
pub struct Alert {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    pub ts_sec: u32,
    pub mitre: Option<MitreTechnique>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub trait DetectionRule: Send {
    fn name(&self) -> &str;
    /// Inspect one packet; return zero or more alerts.
    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert>;
}

// -----------------------------------------------------------------
// Rule 1: Port scan — many distinct destination ports from one source
// within a sliding window, mostly SYN-only (no completed handshake).
// -----------------------------------------------------------------
pub struct PortScanRule {
    window_secs: u32,
    threshold: usize,
    // src_ip -> (window_start, set of dst_ports touched)
    state: HashMap<IpAddr, (u32, HashSet<u16>)>,
}

impl PortScanRule {
    pub fn new(window_secs: u32, threshold: usize) -> Self {
        Self { window_secs, threshold, state: HashMap::new() }
    }
}

impl DetectionRule for PortScanRule {
    fn name(&self) -> &str {
        "port_scan"
    }
    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let Some(L3::Ipv4(ip)) = &pkt.l3 else { return alerts };
        let dst_port = match &pkt.l4 {
            L4::Tcp(t) if t.is_syn() && !t.is_ack() => t.dst_port,
            _ => return alerts,
        };
        let src = IpAddr::V4(ip.src);
        let entry = self.state.entry(src).or_insert((ts_sec, HashSet::new()));
        if ts_sec.saturating_sub(entry.0) > self.window_secs {
            *entry = (ts_sec, HashSet::new());
        }
        entry.1.insert(dst_port);
        let touched = entry.1.len();
        if touched == self.threshold {
            let window_secs = self.window_secs;
            alerts.push(Alert {
                rule: self.name().to_string(),
                severity: Severity::Medium,
                message: format!(
                    "{} touched {} distinct ports on {} in {}s (possible port scan)",
                    src, touched, ip.dst, window_secs
                ),
                ts_sec,
                mitre: built_in_technique(self.name()),
            });
        }
        alerts
    }
}

// -----------------------------------------------------------------
// Rule 2: SYN flood — high rate of SYNs to one destination without
// matching SYN-ACKs, from possibly many sources.
// -----------------------------------------------------------------
pub struct SynFloodRule {
    window_secs: u32,
    syn_threshold: usize,
    state: HashMap<IpAddr, (u32, usize)>, // dst_ip -> (window_start, syn_count)
}

impl SynFloodRule {
    pub fn new(window_secs: u32, syn_threshold: usize) -> Self {
        Self { window_secs, syn_threshold, state: HashMap::new() }
    }
}

impl DetectionRule for SynFloodRule {
    fn name(&self) -> &str {
        "syn_flood"
    }
    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let Some(L3::Ipv4(ip)) = &pkt.l3 else { return alerts };
        let is_syn_only = matches!(&pkt.l4, L4::Tcp(t) if t.is_syn() && !t.is_ack());
        if !is_syn_only {
            return alerts;
        }
        let dst = IpAddr::V4(ip.dst);
        let entry = self.state.entry(dst).or_insert((ts_sec, 0));
        if ts_sec.saturating_sub(entry.0) > self.window_secs {
            *entry = (ts_sec, 0);
        }
        entry.1 += 1;
        let syn_count = entry.1;
        if syn_count == self.syn_threshold {
            let window_secs = self.window_secs;
            alerts.push(Alert {
                rule: self.name().to_string(),
                severity: Severity::High,
                message: format!(
                    "{} received {} SYNs in {}s (possible SYN flood)",
                    dst, syn_count, window_secs
                ),
                ts_sec,
                mitre: built_in_technique(self.name()),
            });
        }
        alerts
    }
}

// -----------------------------------------------------------------
// Rule 3: ARP spoofing — same IP claimed by more than one MAC address.
// -----------------------------------------------------------------
pub struct ArpSpoofRule {
    ip_to_macs: HashMap<std::net::Ipv4Addr, HashSet<[u8; 6]>>,
    alerted_pairs: HashSet<(std::net::Ipv4Addr, [u8; 6])>,
}

impl ArpSpoofRule {
    pub fn new() -> Self {
        Self { ip_to_macs: HashMap::new(), alerted_pairs: HashSet::new() }
    }
}

impl Default for ArpSpoofRule {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionRule for ArpSpoofRule {
    fn name(&self) -> &str {
        "arp_spoof"
    }
    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let Some(L3::Arp { sender_mac, sender_ip, .. }) = &pkt.l3 else { return alerts };
        let macs = self.ip_to_macs.entry(*sender_ip).or_default();
        macs.insert(*sender_mac);
        let mac_count = macs.len();
        if mac_count > 1 && self.alerted_pairs.insert((*sender_ip, *sender_mac)) {
            alerts.push(Alert {
                rule: self.name().to_string(),
                severity: Severity::Critical,
                message: format!(
                    "IP {} claimed by {} different MAC addresses (possible ARP spoofing)",
                    sender_ip, mac_count
                ),
                ts_sec,
                mitre: built_in_technique(self.name()),
            });
        }
        alerts
    }
}

// -----------------------------------------------------------------
// Engine: runs all registered rules over every packet.
// -----------------------------------------------------------------
#[derive(Default)]
pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn with_default_rules() -> Self {
        let mut engine = Self::new();
        engine.register(Box::new(PortScanRule::new(10, 15)));
        engine.register(Box::new(SynFloodRule::new(5, 100)));
        engine.register(Box::new(ArpSpoofRule::new()));
        engine
    }

    pub fn register(&mut self, rule: Box<dyn DetectionRule>) {
        self.rules.push(rule);
    }

    pub fn feed(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut out = Vec::new();
        for rule in self.rules.iter_mut() {
            out.extend(rule.on_packet(pkt, ts_sec));
        }
        out
    }
}
