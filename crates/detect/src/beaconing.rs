//! ndap-detect — C2 Beaconing Detection (Periodicity and Jitter Clustering).
//!
//! Detects covert Command & Control (C2) agents (e.g. Cobalt Strike, Mythic,
//! Metasploit) checking in with external infrastructure at regular intervals
//! with low-to-moderate jitter.
//!
//! Evaluates inter-arrival time deltas Δt, calculating mean interval μ,
//! standard deviation σ, and the Coefficient of Variation (CV = σ / μ).
//! Periodic beaconing with CV <= jitter_threshold triggers an alert.

use crate::{Alert, DetectionRule, Severity};
use ndap_protocol::{DecodedPacket, L3, L4};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct BeaconingRule {
    /// Minimum consecutive intervals required before evaluation (default: 5)
    pub min_samples: usize,
    /// Minimum mean interval in seconds to ignore high-frequency bulk traffic (default: 2.0s)
    pub min_interval_secs: f64,
    /// Maximum allowed Coefficient of Variation (CV = std_dev / mean) for beaconing (default: 0.30)
    pub max_jitter_cv: f64,
    // (src_ip, dst_ip, dst_port) -> list of packet timestamps (seconds)
    flows: HashMap<(IpAddr, IpAddr, u16), Vec<u32>>,
    alerted_flows: HashSet<(IpAddr, IpAddr, u16)>,
}

impl BeaconingRule {
    pub fn new(min_samples: usize, min_interval_secs: f64, max_jitter_cv: f64) -> Self {
        Self {
            min_samples,
            min_interval_secs,
            max_jitter_cv,
            flows: HashMap::new(),
            alerted_flows: HashSet::new(),
        }
    }

    /// Evaluates a sequence of timestamps for periodicity and jitter.
    /// Returns Some((mean_interval, coefficient_of_variation)) if criteria are met.
    pub fn evaluate_intervals(timestamps: &[u32], min_samples: usize, min_interval: f64, max_cv: f64) -> Option<(f64, f64)> {
        if timestamps.len() < min_samples + 1 {
            return None;
        }

        let mut deltas = Vec::with_capacity(timestamps.len() - 1);
        for w in timestamps.windows(2) {
            let dt = w[1].saturating_sub(w[0]) as f64;
            deltas.push(dt);
        }

        if deltas.len() < min_samples {
            return None;
        }

        let count = deltas.len() as f64;
        let sum: f64 = deltas.iter().sum();
        let mean = sum / count;

        if mean < min_interval {
            return None;
        }

        let variance: f64 = deltas.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / count;
        let std_dev = variance.sqrt();
        let cv = std_dev / mean;

        if cv <= max_cv {
            Some((mean, cv))
        } else {
            None
        }
    }
}

impl Default for BeaconingRule {
    fn default() -> Self {
        Self::new(5, 2.0, 0.30)
    }
}

impl DetectionRule for BeaconingRule {
    fn name(&self) -> &str {
        "c2_beaconing"
    }

    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();

        let (src_ip, dst_ip) = match &pkt.l3 {
            Some(L3::Ipv4(ip)) => (IpAddr::V4(ip.src), IpAddr::V4(ip.dst)),
            Some(L3::Ipv6(ip)) => (IpAddr::V6(ip.src), IpAddr::V6(ip.dst)),
            _ => return alerts,
        };

        let dst_port = match &pkt.l4 {
            L4::Tcp(t) => t.dst_port,
            L4::Udp(u) => u.dst_port,
            _ => return alerts,
        };

        let flow_key = (src_ip, dst_ip, dst_port);
        let timestamps = self.flows.entry(flow_key).or_default();

        // Avoid duplicate timestamps from the same burst/retransmit
        if timestamps.last().copied() != Some(ts_sec) {
            timestamps.push(ts_sec);
        }

        // Limit window to 30 most recent samples per flow
        if timestamps.len() > 30 {
            timestamps.remove(0);
        }

        if !self.alerted_flows.contains(&flow_key) {
            if let Some((mean, cv)) = Self::evaluate_intervals(
                timestamps,
                self.min_samples,
                self.min_interval_secs,
                self.max_jitter_cv,
            ) {
                self.alerted_flows.insert(flow_key);
                alerts.push(Alert {
                    rule: "c2_beaconing".to_string(),
                    severity: Severity::Critical,
                    message: format!(
                        "Periodic C2 beaconing detected from {} to {}:{} (mean interval: {:.1}s, jitter CV: {:.2}, samples: {})",
                        src_ip, dst_ip, dst_port, mean, cv, timestamps.len() - 1
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
    fn test_beaconing_detection_with_jitter() {
        let mut rule = BeaconingRule::new(5, 5.0, 0.25);

        // Simulated beaconing every ~60 seconds with +/- 5s jitter:
        // 100, 160, 218, 281, 339, 401
        let beacon_times = [100, 160, 218, 281, 339, 401];

        let mut alerts = Vec::new();
        for &t in &beacon_times {
            let pkt = DecodedPacket {
                eth: None,
                l3: Some(L3::Ipv4(ndap_protocol::Ipv4Header {
                    src: "10.0.0.15".parse().unwrap(),
                    dst: "198.51.100.4".parse().unwrap(),
                    protocol: 6,
                    ttl: 64,
                    total_len: 40,
                })),
                l4: L4::Tcp(ndap_protocol::TcpHeader {
                    src_port: 49876,
                    dst_port: 443,
                    seq: 1,
                    ack: 1,
                    flags: 0x18,
                    window: 65535,
                }),
                payload: vec![],
            };
            alerts.extend(rule.on_packet(&pkt, t));
        }

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "c2_beaconing");
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert!(alerts[0].message.contains("10.0.0.15"));
        assert!(alerts[0].message.contains("198.51.100.4:443"));
    }

    #[test]
    fn test_random_traffic_no_alert() {
        let mut rule = BeaconingRule::new(5, 5.0, 0.25);

        // Highly random intervals (high CV):
        // deltas: 1s, 45s, 3s, 120s, 2s
        let random_times = [100, 101, 146, 149, 269, 271];

        let mut alerts = Vec::new();
        for &t in &random_times {
            let pkt = DecodedPacket {
                eth: None,
                l3: Some(L3::Ipv4(ndap_protocol::Ipv4Header {
                    src: "10.0.0.15".parse().unwrap(),
                    dst: "93.184.216.34".parse().unwrap(),
                    protocol: 6,
                    ttl: 64,
                    total_len: 40,
                })),
                l4: L4::Tcp(ndap_protocol::TcpHeader {
                    src_port: 49876,
                    dst_port: 80,
                    seq: 1,
                    ack: 1,
                    flags: 0x18,
                    window: 65535,
                }),
                payload: vec![],
            };
            alerts.extend(rule.on_packet(&pkt, t));
        }

        assert!(alerts.is_empty(), "Random traffic should not alert on beaconing");
    }
}
