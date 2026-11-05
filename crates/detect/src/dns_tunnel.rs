//! ndap-detect — DNS Tunneling & Exfiltration Detection.
//!
//! Identifies high-entropy query names (e.g. base32/base64/hex data payloads)
//! and unusually long subdomain labels typical of tools like dnscat2, iodine,
//! or Cobalt Strike DNS beacons.

use crate::{Alert, DetectionRule, Severity};
use ndap_protocol::{dns::parse_dns, DecodedPacket, L4};
use std::collections::HashSet;

/// Calculates the Shannon entropy of a string: H = -sum(p * log2(p)).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let total = s.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub struct DnsTunnelRule {
    pub length_threshold: usize,
    pub entropy_threshold: f64,
    seen_queries: HashSet<String>,
}

impl DnsTunnelRule {
    pub fn new(length_threshold: usize, entropy_threshold: f64) -> Self {
        Self {
            length_threshold,
            entropy_threshold,
            seen_queries: HashSet::new(),
        }
    }
}

impl Default for DnsTunnelRule {
    fn default() -> Self {
        Self::new(50, 3.6)
    }
}

impl DetectionRule for DnsTunnelRule {
    fn name(&self) -> &str {
        "dns_tunnel"
    }

    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Check if UDP or TCP DNS traffic
        let is_dns_port = match &pkt.l4 {
            L4::Udp(u) => u.src_port == 53 || u.dst_port == 53,
            L4::Tcp(t) => t.src_port == 53 || t.dst_port == 53,
            _ => false,
        };

        if !is_dns_port && !ndap_protocol::dns::DnsDissector::sniff(&pkt.payload) {
            return alerts;
        }

        let msg = match parse_dns(&pkt.payload) {
            Ok(m) => m,
            Err(_) => return alerts,
        };

        for q in &msg.questions {
            let name = &q.name;
            if name.len() < 12 {
                continue;
            }

            // Extract the subdomain prefix before the registered domain
            let subdomain = match name.rsplitn(3, '.').nth(2) {
                Some(sub) => sub,
                None => name.as_str(),
            };

            let entropy = shannon_entropy(subdomain);
            let is_long = name.len() >= self.length_threshold;
            let is_high_entropy = subdomain.len() >= 20 && entropy >= self.entropy_threshold;

            if (is_long || is_high_entropy) && self.seen_queries.insert(name.clone()) {
                let reason = if is_long && is_high_entropy {
                    format!("query length ({}) and high entropy ({:.2})", name.len(), entropy)
                } else if is_long {
                    format!("unusually long query length ({})", name.len())
                } else {
                    format!("high Shannon entropy ({:.2})", entropy)
                };

                alerts.push(Alert {
                    rule: "dns_tunnel".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Possible DNS tunneling/exfiltration query `{}`: {}",
                        name, reason
                    ),
                    ts_sec,
                });
            }
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
        // Repeated characters have 0 entropy
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
        // Random base64/hex string has high entropy
        let ent = shannon_entropy("c2VjdXJpdHktZGF0YS1leGZpbHRyYXRpb24tZGV0ZWN0aW9u");
        assert!(ent > 3.8);
    }

    #[test]
    fn test_dns_tunnel_detection() {
        let mut rule = DnsTunnelRule::new(40, 3.5);

        // Build synthetic packet querying a suspicious long/high-entropy subdomain
        let suspicious_name = "a8f3b9c1d4e2f7a0b3c6d9e1f4a7b0c3d6e9.tunnel.attacker.com";
        let mut dns_payload = Vec::new();
        dns_payload.extend_from_slice(&[
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // 1 question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        for part in suspicious_name.split('.') {
            dns_payload.push(part.len() as u8);
            dns_payload.extend_from_slice(part.as_bytes());
        }
        dns_payload.push(0x00);
        dns_payload.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT, IN

        let pkt = DecodedPacket {
            eth: None,
            l3: None,
            l4: L4::Udp(ndap_protocol::UdpHeader {
                src_port: 52000,
                dst_port: 53,
                length: (8 + dns_payload.len()) as u16,
            }),
            payload: dns_payload,
        };

        let alerts = rule.on_packet(&pkt, 100);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "dns_tunnel");
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].message.contains("Possible DNS tunneling"));
    }
}
