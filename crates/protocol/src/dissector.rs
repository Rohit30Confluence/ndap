//! ndap-protocol — Phase 2: Dissector registry & plugin framework.

use crate::dns::DnsDissector;
use crate::http::HttpDissector;
use crate::{DecodedPacket, L4};
use std::collections::HashMap;

/// Dissection result containing the protocol name and key-value field tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissectionResult {
    pub protocol: String,
    pub fields: Vec<(String, String)>,
}

impl DissectionResult {
    pub fn get_field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Implement this trait to add a protocol dissector (layer 7 or custom framing).
pub trait Dissector: Send + Sync {
    fn name(&self) -> &str;
    /// Returns a human-readable field tree (name, value).
    fn dissect(&self, payload: &[u8]) -> Vec<(String, String)>;
}

pub struct ProtocolRegistry {
    by_tcp_port: HashMap<u16, Box<dyn Dissector>>,
    by_udp_port: HashMap<u16, Box<dyn Dissector>>,
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            by_tcp_port: HashMap::new(),
            by_udp_port: HashMap::new(),
        }
    }

    /// Creates a registry pre-loaded with built-in dissectors (DNS, HTTP).
    pub fn with_builtin_dissectors() -> Self {
        let mut reg = Self::new();

        // DNS (UDP & TCP port 53)
        reg.register_udp_port(53, Box::new(DnsDissector::new()));
        reg.register_tcp_port(53, Box::new(DnsDissector::new()));

        // HTTP (Standard & common web proxy / app ports)
        let http_ports = [80, 8080, 8000, 8008, 3128, 8888];
        for port in http_ports {
            reg.register_tcp_port(port, Box::new(HttpDissector::new()));
        }

        reg
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

    /// Dissects any decoded packet by inspecting L4 headers and payloads.
    pub fn dissect_packet(&self, pkt: &DecodedPacket) -> Option<DissectionResult> {
        match &pkt.l4 {
            L4::Icmp(icmp) => {
                let mut fields = vec![
                    ("icmp.type".into(), icmp.icmp_type.to_string()),
                    ("icmp.type_name".into(), icmp.type_name().to_string()),
                    ("icmp.code".into(), icmp.code.to_string()),
                    ("icmp.checksum".into(), format!("{:#06x}", icmp.checksum)),
                ];
                if icmp.is_echo_request() || icmp.is_echo_reply() {
                    fields.push(("icmp.id".into(), icmp.echo_id().to_string()));
                    fields.push(("icmp.seq".into(), icmp.echo_seq().to_string()));
                }
                fields.push(("icmp.payload_len".into(), pkt.payload.len().to_string()));
                Some(DissectionResult {
                    protocol: "icmp".into(),
                    fields,
                })
            }
            L4::Udp(u) => {
                if let Some(fields) = self.try_dissect_udp(u.dst_port, &pkt.payload) {
                    return Some(fields);
                }
                if let Some(fields) = self.try_dissect_udp(u.src_port, &pkt.payload) {
                    return Some(fields);
                }
                // Heuristic fallback for non-standard ports
                if DnsDissector::sniff(&pkt.payload) {
                    let d = DnsDissector::new();
                    let fields = d.dissect(&pkt.payload);
                    if !fields.is_empty() {
                        return Some(DissectionResult {
                            protocol: "dns".into(),
                            fields,
                        });
                    }
                }
                None
            }
            L4::Tcp(t) => {
                if let Some(fields) = self.try_dissect_tcp(t.dst_port, &pkt.payload) {
                    return Some(fields);
                }
                if let Some(fields) = self.try_dissect_tcp(t.src_port, &pkt.payload) {
                    return Some(fields);
                }
                // Heuristic fallback for non-standard ports
                if HttpDissector::sniff(&pkt.payload) {
                    let d = HttpDissector::new();
                    let fields = d.dissect(&pkt.payload);
                    if !fields.is_empty() {
                        return Some(DissectionResult {
                            protocol: "http".into(),
                            fields,
                        });
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn try_dissect_udp(&self, port: u16, payload: &[u8]) -> Option<DissectionResult> {
        let dissector = self.by_udp_port.get(&port)?;
        let fields = dissector.dissect(payload);
        if fields.is_empty() {
            None
        } else {
            Some(DissectionResult {
                protocol: dissector.name().to_string(),
                fields,
            })
        }
    }

    fn try_dissect_tcp(&self, port: u16, payload: &[u8]) -> Option<DissectionResult> {
        let dissector = self.by_tcp_port.get(&port)?;
        let fields = dissector.dissect(payload);
        if fields.is_empty() {
            None
        } else {
            Some(DissectionResult {
                protocol: dissector.name().to_string(),
                fields,
            })
        }
    }
}

/// Plugin loader interface for dynamic dissectors.
pub trait PluginLoader {
    fn load_plugins(&self, dir: &str, registry: &mut ProtocolRegistry) -> Result<usize, String>;
}

pub struct NoopPluginLoader;
impl PluginLoader for NoopPluginLoader {
    fn load_plugins(&self, _dir: &str, _registry: &mut ProtocolRegistry) -> Result<usize, String> {
        Ok(0)
    }
}
