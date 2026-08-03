//! Out-of-process Python plugin support (JSON-lines over stdin/stdout).
//!
//! Decision: subprocess isolation over embedding (PyO3). A malformed or
//! malicious community plugin can only crash its own process or hang on a
//! read/write, not touch the Rust core's memory. Cost is one process per
//! plugin and JSON-encode/decode per packet — acceptable for a detection
//! engine (not a full-line-rate capture path).
//!
//! Protocol: one JSON object per line on stdin (see `PyPacket`), one JSON
//! array (possibly empty) of alerts per line on stdout (see `PyAlertWire`).
//! The runner script lives at `plugins/python-sdk/plugin_runner.py`.

use crate::{Alert, DetectionRule, Severity};
use ndap_protocol::{DecodedPacket, L3, L4};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[derive(Serialize)]
struct PyPacket {
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
struct PyAlertWire {
    rule: String,
    severity: String,
    message: String,
}

fn to_py_packet(pkt: &DecodedPacket, ts_sec: u32) -> Option<PyPacket> {
    let (src_ip, dst_ip) = match &pkt.l3 {
        Some(L3::Ipv4(h)) => (h.src.to_string(), h.dst.to_string()),
        Some(L3::Ipv6(h)) => (h.src.to_string(), h.dst.to_string()),
        _ => return None,
    };
    let (src_port, dst_port, protocol, flags) = match &pkt.l4 {
        L4::Tcp(t) => (
            t.src_port,
            t.dst_port,
            "tcp".to_string(),
            Some(format!(
                "{}{}{}{}",
                if t.is_syn() { "S" } else { "" },
                if t.is_ack() { "A" } else { "" },
                if t.is_fin() { "F" } else { "" },
                if t.is_rst() { "R" } else { "" },
            )),
        ),
        L4::Udp(u) => (u.src_port, u.dst_port, "udp".to_string(), None),
        _ => (0, 0, "other".to_string(), None),
    };
    Some(PyPacket {
        ts_sec,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        flags,
        payload_hex: hex_encode(&pkt.payload),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn severity_from_str(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// A detection rule implemented in Python, running as a child process.
pub struct PyPluginRule {
    name: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

#[derive(Debug)]
pub enum PluginError {
    Spawn(std::io::Error),
    Io(std::io::Error),
    Protocol(String),
}

impl PyPluginRule {
    /// `runner_path`: path to `plugin_runner.py`.
    /// `plugin_path`: path to the user's plugin .py file.
    /// `class_name`: the `DetectionRule` subclass to instantiate.
    pub fn spawn(runner_path: &str, plugin_path: &str, class_name: &str) -> Result<Self, PluginError> {
        let mut child = Command::new("python3")
            .arg("-u")
            .arg(runner_path)
            .arg(plugin_path)
            .arg(class_name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(PluginError::Spawn)?;

        let stdin = child.stdin.take().ok_or_else(|| {
            PluginError::Protocol("failed to open plugin stdin".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            PluginError::Protocol("failed to open plugin stdout".to_string())
        })?;

        Ok(Self {
            name: format!("py:{class_name}"),
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn send_and_receive(&mut self, pkt: &PyPacket, ts_sec: u32) -> Result<Vec<Alert>, PluginError> {
        let line = serde_json::to_string(pkt).map_err(|e| PluginError::Protocol(e.to_string()))?;
        writeln!(self.stdin, "{line}").map_err(PluginError::Io)?;
        self.stdin.flush().map_err(PluginError::Io)?;

        let mut response = String::new();
        self.stdout.read_line(&mut response).map_err(PluginError::Io)?;
        if response.trim().is_empty() {
            return Ok(Vec::new());
        }
        let wire: Vec<PyAlertWire> =
            serde_json::from_str(response.trim()).map_err(|e| PluginError::Protocol(e.to_string()))?;
        Ok(wire
            .into_iter()
            .map(|a| Alert {
                rule: a.rule,
                severity: severity_from_str(&a.severity),
                message: a.message,
                ts_sec,
                mitre: None, // plugin authors can encode MITRE mapping in `message` for v0
            })
            .collect())
    }
}

impl DetectionRule for PyPluginRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_packet(&mut self, pkt: &DecodedPacket, ts_sec: u32) -> Vec<Alert> {
        let Some(py_pkt) = to_py_packet(pkt, ts_sec) else { return Vec::new() };
        match self.send_and_receive(&py_pkt, ts_sec) {
            Ok(alerts) => alerts,
            Err(_e) => Vec::new(), // a misbehaving plugin degrades silently rather than killing the pipeline
        }
    }
}

impl Drop for PyPluginRule {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndap_protocol::{decode_packet};

    #[test]
    fn python_plugin_ipc_roundtrip() {
        let runner = concat!(env!("CARGO_MANIFEST_DIR"), "/../../plugins/python-sdk/plugin_runner.py");
        let plugin = concat!(env!("CARGO_MANIFEST_DIR"), "/../../plugins/python-sdk/ndap_plugin.py");
        let mut rule = PyPluginRule::spawn(runner, plugin, "ExampleDnsTunnelRule")
            .expect("failed to spawn python plugin — is python3 on PATH?");

        // Build a raw UDP/53 packet with a long payload to trigger the example rule
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0x11,0x22,0x33,0x44,0x55,0x66]); // dst mac
        raw.extend_from_slice(&[0xaa,0xbb,0xcc,0xdd,0xee,0xff]); // src mac
        raw.extend_from_slice(&[0x08,0x00]); // ethertype IPv4
        let udp_payload = vec![b'A'; 80]; // > 60 byte threshold in the example rule
        let udp_len = 8 + udp_payload.len();
        // IPv4 header
        raw.extend_from_slice(&[0x45,0x00]);
        raw.extend_from_slice(&((20+udp_len) as u16).to_be_bytes());
        raw.extend_from_slice(&[0,0,0,0,64,17,0,0]);
        raw.extend_from_slice(&[10,0,0,66]);
        raw.extend_from_slice(&[10,0,0,1]);
        // UDP header: src 40000 dst 53
        raw.extend_from_slice(&40000u16.to_be_bytes());
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.extend_from_slice(&(udp_len as u16).to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&udp_payload);

        let decoded = decode_packet(&raw);
        let alerts = rule.on_packet(&decoded, 42);
        assert_eq!(alerts.len(), 1, "expected the example plugin rule to fire");
        assert_eq!(alerts[0].rule, "dns_tunnel_example");
        assert_eq!(alerts[0].ts_sec, 42);
    }
}
