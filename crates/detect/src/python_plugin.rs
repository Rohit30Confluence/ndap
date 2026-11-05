//! ndap-detect — Out-of-process Python Plugin Rule Runner.
//!
//! Spawns Python plugins as separate processes communicating over
//! JSON-lines via stdin and stdout. This ensures plugin isolation: a
//! crashing, slow, or faulty Python script cannot crash the Rust core.

use crate::{Alert, DetectionRule, Severity};
use ndap_protocol::{DecodedPacket, L3, L4};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[derive(Serialize)]
struct PacketEvent {
    ts_sec: u32,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    flags: Option<String>,
    payload_hex: String,
}

#[derive(Deserialize)]
struct PluginResponse {
    #[serde(default)]
    alerts: Vec<PluginAlert>,
    #[allow(dead_code)]
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct PluginAlert {
    rule: String,
    severity: String,
    message: String,
}

pub struct PythonPluginRule {
    name: String,
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl PythonPluginRule {
    /// Spawns a Python plugin script via `python3`.
    pub fn spawn(script_path: &str) -> std::io::Result<Self> {
        let rule_name = Path::new(script_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("python_plugin")
            .to_string();

        Self::from_command("python3", &[script_path], rule_name)
    }

    /// Spawns a plugin using custom interpreter binary and arguments.
    pub fn from_command(program: &str, args: &[&str], rule_name: String) -> std::io::Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = BufWriter::new(child.stdin.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "failed to open plugin stdin")
        })?);

        let stdout = BufReader::new(child.stdout.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "failed to open plugin stdout")
        })?);

        Ok(Self {
            name: rule_name,
            child,
            stdin,
            stdout,
        })
    }
}

impl DetectionRule for PythonPluginRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Extract metadata for the Python plugin
        let (src_ip, dst_ip) = match &pkt.l3 {
            Some(L3::Ipv4(ip)) => (ip.src.to_string(), ip.dst.to_string()),
            Some(L3::Ipv6(ip)) => (ip.src.to_string(), ip.dst.to_string()),
            Some(L3::Arp { sender_ip, target_ip, .. }) => (sender_ip.to_string(), target_ip.to_string()),
            _ => (String::new(), String::new()),
        };

        let (src_port, dst_port, protocol, flags) = match &pkt.l4 {
            L4::Tcp(t) => {
                let mut f = Vec::new();
                if t.is_syn() { f.push("SYN"); }
                if t.is_ack() { f.push("ACK"); }
                if t.is_fin() { f.push("FIN"); }
                if t.is_rst() { f.push("RST"); }
                (t.src_port, t.dst_port, "tcp".to_string(), Some(f.join("|")))
            }
            L4::Udp(u) => (u.src_port, u.dst_port, "udp".to_string(), None),
            L4::Icmp(_) => (0, 0, "icmp".to_string(), None),
            L4::Other(o) => (0, 0, format!("other({o})"), None),
            L4::None => (0, 0, "none".to_string(), None),
        };

        let payload_hex: String = pkt.payload.iter().map(|b| format!("{b:02x}")).collect();

        let event = PacketEvent {
            ts_sec,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            flags,
            payload_hex,
        };

        // Send JSON line to Python plugin
        if serde_json::to_writer(&mut self.stdin, &event).is_err() {
            return alerts;
        }
        if writeln!(&mut self.stdin).is_err() || self.stdin.flush().is_err() {
            return alerts;
        }

        // Read JSON line response from Python plugin
        let mut response_line = String::new();
        if self.stdout.read_line(&mut response_line).is_err() || response_line.is_empty() {
            return alerts;
        }

        if let Ok(resp) = serde_json::from_str::<PluginResponse>(&response_line) {
            for a in resp.alerts {
                let severity = match a.severity.to_ascii_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    _ => Severity::Low,
                };
                alerts.push(Alert {
                    rule: a.rule,
                    severity,
                    message: a.message,
                    ts_sec,
                });
            }
        }

        alerts
    }
}

impl Drop for PythonPluginRule {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_plugin_ipc_roundtrip() {
        // Write a temporary standalone Python rule for unit testing
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("ndap_test_ipc_rule.py");

        let script = r#"
import sys, json

for line in sys.stdin:
    if not line.strip():
        continue
    data = json.loads(line)
    alerts = []
    if data.get("dst_port") == 1337:
        alerts.append({
            "rule": "custom_python_backdoor",
            "severity": "critical",
            "message": f"Backdoor port 1337 accessed from {data.get('src_ip')}"
        })
    sys.stdout.write(json.dumps({"alerts": alerts}) + "\n")
    sys.stdout.flush()
"#;
        std::fs::write(&script_path, script).expect("write temp python rule");

        let mut plugin = PythonPluginRule::spawn(script_path.to_str().unwrap())
            .expect("spawn python plugin rule");

        // Send a normal packet
        let normal_pkt = DecodedPacket {
            eth: None,
            l3: Some(L3::Ipv4(ndap_protocol::Ipv4Header {
                src: "10.0.0.1".parse().unwrap(),
                dst: "10.0.0.2".parse().unwrap(),
                protocol: 6,
                ttl: 64,
                total_len: 40,
            })),
            l4: L4::Tcp(ndap_protocol::TcpHeader {
                src_port: 50000,
                dst_port: 80,
                seq: 1,
                ack: 1,
                flags: 0x02,
                window: 65535,
            }),
            payload: vec![],
        };
        let alerts = plugin.on_packet(&normal_pkt, 100);
        assert!(alerts.is_empty());

        // Send a packet targeting port 1337
        let attack_pkt = DecodedPacket {
            eth: None,
            l3: Some(L3::Ipv4(ndap_protocol::Ipv4Header {
                src: "192.168.1.99".parse().unwrap(),
                dst: "192.168.1.1".parse().unwrap(),
                protocol: 6,
                ttl: 64,
                total_len: 40,
            })),
            l4: L4::Tcp(ndap_protocol::TcpHeader {
                src_port: 50000,
                dst_port: 1337,
                seq: 1,
                ack: 1,
                flags: 0x02,
                window: 65535,
            }),
            payload: vec![],
        };
        let alerts = plugin.on_packet(&attack_pkt, 101);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "custom_python_backdoor");
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert!(alerts[0].message.contains("192.168.1.99"));

        let _ = std::fs::remove_file(script_path);
    }
}
