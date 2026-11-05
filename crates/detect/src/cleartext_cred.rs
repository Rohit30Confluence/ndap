//! ndap-detect — Cleartext Credential Exposure Detection.
//!
//! Identifies sensitive credentials (HTTP Basic Auth headers, plaintext passwords,
//! secret API keys) transmitted without TLS encryption over HTTP.

use crate::{Alert, DetectionRule, Severity};
use ndap_protocol::{http::parse_http, DecodedPacket, HttpMessage, L4};
use std::collections::HashSet;

pub struct CleartextCredentialRule {
    alerted_targets: HashSet<String>,
}

impl CleartextCredentialRule {
    pub fn new() -> Self {
        Self {
            alerted_targets: HashSet::new(),
        }
    }
}

impl Default for CleartextCredentialRule {
    fn default() -> Self {
        Self::new()
    }
}

const SENSITIVE_QUERY_KEYWORDS: &[&str] = &[
    "password=",
    "passwd=",
    "pwd=",
    "secret=",
    "api_key=",
    "apikey=",
    "access_token=",
    "auth_token=",
];

const SENSITIVE_BODY_PATTERNS: &[&str] = &[
    "password=",
    "passwd=",
    "\"password\":",
    "\"passwd\":",
    "\"secret\":",
    "\"api_key\":",
];

impl DetectionRule for CleartextCredentialRule {
    fn name(&self) -> &str {
        "cleartext_credentials"
    }

    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Check if TCP web port or HTTP payload
        let is_http_port = match &pkt.l4 {
            L4::Tcp(t) => {
                let p1 = t.src_port;
                let p2 = t.dst_port;
                p1 == 80 || p2 == 80 || p1 == 8080 || p2 == 8080 || p1 == 8000 || p2 == 8000
            }
            _ => false,
        };

        if !is_http_port && !ndap_protocol::http::HttpDissector::sniff(&pkt.payload) {
            return alerts;
        }

        let msg = match parse_http(&pkt.payload) {
            Ok(m) => m,
            Err(_) => return alerts,
        };

        if let HttpMessage::Request(req) = msg {
            let host = req.host().unwrap_or("unknown-host");

            // 1. HTTP Basic Authentication header
            if let Some(auth) = req.get_header("Authorization") {
                if auth.to_ascii_lowercase().starts_with("basic ") {
                    let key = format!("{}:{}:basic", host, req.uri);
                    if self.alerted_targets.insert(key) {
                        alerts.push(Alert {
                            rule: "cleartext_credentials".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "HTTP Basic Authentication transmitted unencrypted to {} (URI: {})",
                                host, req.uri
                            ),
                            ts_sec,
                        });
                    }
                }
            }

            // 2. Sensitive query parameters in URI
            let uri_lower = req.uri.to_ascii_lowercase();
            for &kw in SENSITIVE_QUERY_KEYWORDS {
                if uri_lower.contains(kw) {
                    let key = format!("{}:{}:uri_param", host, req.uri);
                    if self.alerted_targets.insert(key) {
                        alerts.push(Alert {
                            rule: "cleartext_credentials".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Sensitive credential parameter `{}` exposed in unencrypted HTTP URI on {} ({})",
                                kw.trim_end_matches('='), host, req.uri
                            ),
                            ts_sec,
                        });
                    }
                    break;
                }
            }

            // 3. Sensitive credentials in POST/PUT body
            if req.body_len > 0 && req.body_offset < pkt.payload.len() {
                let body_slice = &pkt.payload[req.body_offset..];
                let body_str = String::from_utf8_lossy(body_slice).to_ascii_lowercase();
                for &pattern in SENSITIVE_BODY_PATTERNS {
                    if body_str.contains(pattern) {
                        let key = format!("{}:{}:body", host, req.uri);
                        if self.alerted_targets.insert(key) {
                            alerts.push(Alert {
                                rule: "cleartext_credentials".to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Plaintext credential parameter `{}` submitted in unencrypted HTTP body to {} ({})",
                                    pattern.trim_matches(|c| c == '"' || c == '=' || c == ':'),
                                    host,
                                    req.uri
                                ),
                                ts_sec,
                            });
                        }
                        break;
                    }
                }
            }
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_basic_auth() {
        let mut rule = CleartextCredentialRule::new();
        let http_raw = b"GET /admin/dashboard HTTP/1.1\r\n\
Host: internal.corp.net\r\n\
Authorization: Basic dXNlcjpzZWNyZXQxMjM=\r\n\
\r\n";

        let pkt = DecodedPacket {
            eth: None,
            l3: None,
            l4: L4::Tcp(ndap_protocol::TcpHeader {
                src_port: 51234,
                dst_port: 80,
                seq: 1,
                ack: 1,
                flags: 0x18,
                window: 65535,
            }),
            payload: http_raw.to_vec(),
        };

        let alerts = rule.on_packet(&pkt, 10);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "cleartext_credentials");
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].message.contains("HTTP Basic Authentication"));
    }

    #[test]
    fn test_detect_credential_query_param() {
        let mut rule = CleartextCredentialRule::new();
        let http_raw = b"GET /login?user=admin&password=mySuperPassword HTTP/1.1\r\n\
Host: legacy.app.local\r\n\
\r\n";

        let pkt = DecodedPacket {
            eth: None,
            l3: None,
            l4: L4::Tcp(ndap_protocol::TcpHeader {
                src_port: 51234,
                dst_port: 80,
                seq: 1,
                ack: 1,
                flags: 0x18,
                window: 65535,
            }),
            payload: http_raw.to_vec(),
        };

        let alerts = rule.on_packet(&pkt, 11);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("password"));
    }
}
