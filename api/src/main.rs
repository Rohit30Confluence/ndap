//! ndap-api — Phase 6: REST API, Real-Time WebSocket Streaming, and Dashboard.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Json, State,
    },
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use ndap_detect::DetectionEngine;
use ndap_flow::ConversationTracker;
use ndap_intel::{IocFeedSource, IocStats, IocStore, IocSyncManager};
use ndap_protocol::{decode_packet, DecodedPacket, ProtocolRegistry, L3, L4};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LiveFeedEvent {
    #[serde(rename = "packet")]
    Packet {
        ts_sec: u32,
        src: String,
        dst: String,
        proto: String,
        len: usize,
        summary: String,
    },
    #[serde(rename = "alert")]
    Alert {
        ts_sec: u32,
        rule: String,
        severity: String,
        message: String,
        mitre_id: Option<String>,
        mitre_name: Option<String>,
    },
    #[serde(rename = "stats")]
    Stats {
        packets: u64,
        conversations: usize,
        alerts: u64,
    },
    #[serde(rename = "status")]
    Status {
        capturing: bool,
        message: String,
    },
}

#[derive(Default, Clone, Serialize)]
pub struct LiveStats {
    pub packets: u64,
    pub conversations: usize,
    pub alerts: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<LiveFeedEvent>,
    pub is_capturing: Arc<AtomicBool>,
    pub live_stats: Arc<tokio::sync::RwLock<LiveStats>>,
    pub ioc_mgr: Arc<IocSyncManager>,
}

#[derive(Deserialize)]
struct AnalyzeRequest {
    path: String,
}

#[derive(Serialize)]
struct AlertOut {
    ts_sec: u32,
    rule: String,
    severity: String,
    message: String,
    mitre_id: Option<String>,
    mitre_name: Option<String>,
}

#[derive(Serialize)]
struct AnalyzeResponse {
    packets: u64,
    conversations: usize,
    protocols: HashMap<String, u64>,
    alerts: Vec<AlertOut>,
}

#[derive(Deserialize, Default)]
struct CaptureStartRequest {
    path: Option<String>,
    interval_ms: Option<u64>,
}

async fn health() -> &'static str {
    "ok"
}

fn packet_summary(decoded: &DecodedPacket, registry: &ProtocolRegistry) -> (String, String, String, String) {
    let (src, dst) = match &decoded.l3 {
        Some(L3::Ipv4(ip)) => {
            let s_ip = ip.src.to_string();
            let d_ip = ip.dst.to_string();
            match &decoded.l4 {
                L4::Tcp(t) => (format!("{}:{}", s_ip, t.src_port), format!("{}:{}", d_ip, t.dst_port)),
                L4::Udp(u) => (format!("{}:{}", s_ip, u.src_port), format!("{}:{}", d_ip, u.dst_port)),
                _ => (s_ip, d_ip),
            }
        }
        Some(L3::Ipv6(ip)) => {
            let s_ip = ip.src.to_string();
            let d_ip = ip.dst.to_string();
            match &decoded.l4 {
                L4::Tcp(t) => (format!("{}:{}", s_ip, t.src_port), format!("{}:{}", d_ip, t.dst_port)),
                L4::Udp(u) => (format!("{}:{}", s_ip, u.src_port), format!("{}:{}", d_ip, u.dst_port)),
                _ => (s_ip, d_ip),
            }
        }
        Some(L3::Arp { sender_ip, target_ip, .. }) => (sender_ip.to_string(), target_ip.to_string()),
        _ => ("—".into(), "—".into()),
    };

    let (proto, summary) = if let Some(dissection) = decoded.dissect(registry) {
        let proto = dissection.protocol.to_uppercase();
        let summary = match dissection.protocol.as_str() {
            "dns" => {
                if let Some(name) = dissection.get_field("dns.qry.name") {
                    let qr = dissection.get_field("dns.flags.qr").unwrap_or("query");
                    format!("DNS {}: {}", qr, name)
                } else {
                    "DNS Message".into()
                }
            }
            "http" => {
                if let Some(m) = dissection
                    .get_field("http.method")
                    .or_else(|| dissection.get_field("http.request.method"))
                {
                    let u = dissection
                        .get_field("http.request_uri")
                        .or_else(|| dissection.get_field("http.request.uri"))
                        .unwrap_or("/");
                    format!("HTTP {} {}", m, u)
                } else if let Some(sc) = dissection
                    .get_field("http.status_code")
                    .or_else(|| dissection.get_field("http.response.code"))
                {
                    let reason = dissection
                        .get_field("http.reason")
                        .or_else(|| dissection.get_field("http.response.phrase"))
                        .unwrap_or("");
                    format!("HTTP {} {}", sc, reason)
                } else {
                    "HTTP Message".into()
                }
            }
            _ => format!("{} traffic", proto),
        };
        (proto, summary)
    } else {
        match &decoded.l4 {
            L4::Tcp(t) => {
                let mut flags = Vec::new();
                if t.is_syn() { flags.push("SYN"); }
                if t.is_ack() { flags.push("ACK"); }
                if t.is_fin() { flags.push("FIN"); }
                if t.is_rst() { flags.push("RST"); }
                ("TCP".into(), format!("TCP [{}] Seq={}", flags.join(","), t.seq))
            }
            L4::Udp(_) => ("UDP".into(), "UDP datagram".into()),
            L4::Icmp(_) => {
                if let Ok((icmp, _)) = ndap_protocol::decode_icmp(&decoded.payload) {
                    ("ICMP".into(), format!("ICMP type={} code={}", icmp.icmp_type, icmp.code))
                } else {
                    ("ICMP".into(), "ICMP message".into())
                }
            }
            _ => match &decoded.l3 {
                Some(L3::Arp { op, .. }) => ("ARP".into(), format!("ARP op={}", op)),
                _ => ("RAW".into(), "Raw frame".into()),
            }
        }
    };

    (src, dst, proto, summary)
}

async fn analyze(
    State(state): State<AppState>,
    Json(req): Json<AnalyzeRequest>,
) -> Json<AnalyzeResponse> {
    let mut tracker = ConversationTracker::new();
    let mut engine = DetectionEngine::with_default_rules();
    let registry = ProtocolRegistry::with_builtin_dissectors();
    let mut packets = 0u64;
    let mut protocols: HashMap<String, u64> = HashMap::new();
    let mut alerts = Vec::new();

    match ndap_capture::PcapReader::open(&req.path) {
        Ok(reader) => {
            for raw in reader {
                let Ok(raw) = raw else { break };
                packets += 1;
                let decoded = decode_packet(&raw.data);
                tracker.record(&decoded, raw.ts_sec, raw.ts_usec);

                // Track layer 3 & 4 protocol distribution
                match &decoded.l3 {
                    Some(L3::Arp { .. }) => { *protocols.entry("ARP".into()).or_default() += 1; }
                    Some(L3::Ipv4(_)) => { *protocols.entry("IPv4".into()).or_default() += 1; }
                    Some(L3::Ipv6(_)) => { *protocols.entry("IPv6".into()).or_default() += 1; }
                    _ => {}
                }
                match &decoded.l4 {
                    L4::Tcp(_) => { *protocols.entry("TCP".into()).or_default() += 1; }
                    L4::Udp(_) => { *protocols.entry("UDP".into()).or_default() += 1; }
                    L4::Icmp(_) => { *protocols.entry("ICMP".into()).or_default() += 1; }
                    _ => {}
                }

                // Layer 7 Application dissections (DNS, HTTP)
                if let Some(dissection) = decoded.dissect(&registry) {
                    *protocols.entry(dissection.protocol.to_uppercase()).or_default() += 1;
                }

                let (src, dst, proto, summary) = packet_summary(&decoded, &registry);

                // Stream packet over WebSocket broadcast
                let _ = state.tx.send(LiveFeedEvent::Packet {
                    ts_sec: raw.ts_sec,
                    src,
                    dst,
                    proto,
                    len: raw.data.len(),
                    summary,
                });

                for a in engine.feed(&decoded, raw.ts_sec) {
                    let mitre = ndap_intel::mitre_for_rule(&a.rule);
                    let alert_out = AlertOut {
                        ts_sec: a.ts_sec,
                        rule: a.rule.clone(),
                        severity: format!("{:?}", a.severity),
                        message: a.message.clone(),
                        mitre_id: mitre.as_ref().map(|m| m.id.clone()),
                        mitre_name: mitre.as_ref().map(|m| m.name.clone()),
                    };

                    let _ = state.tx.send(LiveFeedEvent::Alert {
                        ts_sec: alert_out.ts_sec,
                        rule: alert_out.rule.clone(),
                        severity: alert_out.severity.clone(),
                        message: alert_out.message.clone(),
                        mitre_id: alert_out.mitre_id.clone(),
                        mitre_name: alert_out.mitre_name.clone(),
                    });

                    alerts.push(alert_out);
                }
            }
        }
        Err(e) => {
            alerts.push(AlertOut {
                ts_sec: 0,
                rule: "system".into(),
                severity: "Error".into(),
                message: format!("failed to open pcap: {e:?}"),
                mitre_id: None,
                mitre_name: None,
            });
        }
    }

    let _ = state.tx.send(LiveFeedEvent::Stats {
        packets,
        conversations: tracker.conversations.len(),
        alerts: alerts.len() as u64,
    });

    Json(AnalyzeResponse {
        packets,
        conversations: tracker.conversations.len(),
        protocols,
        alerts,
    })
}

// ---------------------------------------------------------------------
// WebSocket Live Handler
// ---------------------------------------------------------------------

async fn ws_live_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state))
}

async fn handle_ws_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.tx.subscribe();

    // Send initial stats on connect
    let current_stats = state.live_stats.read().await.clone();
    let initial = LiveFeedEvent::Stats {
        packets: current_stats.packets,
        conversations: current_stats.conversations,
        alerts: current_stats.alerts,
    };
    if let Ok(json) = serde_json::to_string(&initial) {
        let _ = socket.send(Message::Text(json)).await;
    }

    while let Ok(event) = rx.recv().await {
        if let Ok(json) = serde_json::to_string(&event) {
            if socket.send(Message::Text(json)).await.is_err() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------
// Synthetic Packet Crafting for Instant Demonstration
// ---------------------------------------------------------------------

fn craft_ipv4_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    proto: u8,
    l4_payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14 + 20 + l4_payload.len());
    // Ethernet header
    packet.extend_from_slice(&[0x00, 0x50, 0x56, 0xc0, 0x00, 0x01]); // dst mac
    packet.extend_from_slice(&[0x00, 0x0c, 0x29, 0x6e, 0x4a, 0x82]); // src mac
    packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // IPv4 header (20 bytes)
    let total_len = (20 + l4_payload.len()) as u16;
    packet.push(0x45); // Version 4, IHL 5
    packet.push(0x00); // DSCP/ECN
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[0x1a, 0x2b]); // Identification
    packet.extend_from_slice(&[0x40, 0x00]); // Don't fragment
    packet.push(64); // TTL
    packet.push(proto); // Protocol (6=TCP, 17=UDP, 1=ICMP)
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
    packet.extend_from_slice(&src_ip);
    packet.extend_from_slice(&dst_ip);

    // Compute IPv4 header checksum
    let mut sum: u32 = 0;
    for i in (14..34).step_by(2) {
        let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    packet[24..26].copy_from_slice(&csum.to_be_bytes());

    // L4 + payload
    packet.extend_from_slice(l4_payload);
    packet
}

fn craft_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    let len = (8 + payload.len()) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // Checksum optional
    out.extend_from_slice(payload);
    out
}

fn craft_tcp(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    out.push(0x50); // Data offset (5 * 4 = 20 bytes)
    out.push(flags); // SYN=0x02, ACK=0x10, PSH|ACK=0x18
    out.extend_from_slice(&65535u16.to_be_bytes()); // Window
    out.extend_from_slice(&[0x00, 0x00]); // Checksum
    out.extend_from_slice(&[0x00, 0x00]); // Urgent ptr
    out.extend_from_slice(payload);
    out
}

fn craft_dns_query(qname: &str) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&[0x12, 0x34]); // Transaction ID
    dns.extend_from_slice(&[0x01, 0x00]); // Standard query
    dns.extend_from_slice(&[0x00, 0x01]); // 1 question
    dns.extend_from_slice(&[0x00, 0x00]); // 0 answers
    dns.extend_from_slice(&[0x00, 0x00]); // 0 auth
    dns.extend_from_slice(&[0x00, 0x00]); // 0 add

    for part in qname.split('.') {
        dns.push(part.len() as u8);
        dns.extend_from_slice(part.as_bytes());
    }
    dns.push(0x00); // Root label
    dns.extend_from_slice(&[0x00, 0x01]); // Type A
    dns.extend_from_slice(&[0x00, 0x01]); // Class IN
    dns
}

// ---------------------------------------------------------------------
// Capture Management Endpoints
// ---------------------------------------------------------------------

async fn capture_start(
    State(state): State<AppState>,
    Json(req): Json<CaptureStartRequest>,
) -> Json<serde_json::Value> {
    if state.is_capturing.load(Ordering::SeqCst) {
        return Json(serde_json::json!({
            "status": "already_running",
            "message": "Live capture feed is already running"
        }));
    }

    state.is_capturing.store(true, Ordering::SeqCst);
    let state_clone = state.clone();

    tokio::spawn(async move {
        let is_capturing = state_clone.is_capturing.clone();
        let tx = state_clone.tx.clone();
        let live_stats = state_clone.live_stats.clone();
        let registry = ProtocolRegistry::with_builtin_dissectors();
        let mut tracker = ConversationTracker::new();
        let mut engine = DetectionEngine::with_default_rules();

        let _ = tx.send(LiveFeedEvent::Status {
            capturing: true,
            message: "Live network feed started".into(),
        });

        let sleep_ms = req.interval_ms.unwrap_or(120);

        if let Some(pcap_path) = req.path {
            match ndap_capture::PcapReader::open(&pcap_path) {
                Ok(reader) => {
                    for raw in reader {
                        if !is_capturing.load(Ordering::SeqCst) {
                            break;
                        }
                        let Ok(raw) = raw else { break };
                        let decoded = decode_packet(&raw.data);
                        tracker.record(&decoded, raw.ts_sec, raw.ts_usec);

                        let (src, dst, proto, summary) = packet_summary(&decoded, &registry);
                        let _ = tx.send(LiveFeedEvent::Packet {
                            ts_sec: raw.ts_sec,
                            src,
                            dst,
                            proto,
                            len: raw.data.len(),
                            summary,
                        });

                        for a in engine.feed(&decoded, raw.ts_sec) {
                            let mitre = ndap_intel::mitre_for_rule(&a.rule);
                            let _ = tx.send(LiveFeedEvent::Alert {
                                ts_sec: a.ts_sec,
                                rule: a.rule,
                                severity: format!("{:?}", a.severity),
                                message: a.message,
                                mitre_id: mitre.as_ref().map(|m| m.id.clone()),
                                mitre_name: mitre.as_ref().map(|m| m.name.clone()),
                            });

                            let mut stats = live_stats.write().await;
                            stats.alerts += 1;
                        }

                        {
                            let mut stats = live_stats.write().await;
                            stats.packets += 1;
                            stats.conversations = tracker.conversations.len();
                        }

                        tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
                    }
                }
                Err(e) => {
                    let _ = tx.send(LiveFeedEvent::Alert {
                        ts_sec: 0,
                        rule: "capture_error".into(),
                        severity: "High".into(),
                        message: format!("Failed to open pcap `{pcap_path}`: {e:?}"),
                        mitre_id: None,
                        mitre_name: None,
                    });
                }
            }
        } else {
            // Synthetic Live Stream: generates realistic traffic including C2 Beaconing,
            // DNS tunneling, and cleartext credential alerts in real time
            let mut step = 0u64;
            let base_ts = 1_700_000_000u32;

            while is_capturing.load(Ordering::SeqCst) {
                step += 1;
                let ts_sec = base_ts + (step * 2) as u32;

                let (packet_bytes, summary_override) = match step % 7 {
                    0 => {
                        // Regular Web HTTPS connection
                        let tcp = craft_tcp(54320 + (step as u16 % 100), 443, step as u32 * 100, 0, 0x02, &[]);
                        (craft_ipv4_packet([192, 168, 1, 50], [140, 82, 121, 4], 6, &tcp), None)
                    }
                    1 => {
                        // Standard DNS query
                        let dns = craft_dns_query("api.github.com");
                        let udp = craft_udp(51234, 53, &dns);
                        (craft_ipv4_packet([192, 168, 1, 50], [8, 8, 8, 8], 17, &udp), None)
                    }
                    2 => {
                        // Cleartext Credentials (HTTP Basic Auth)
                        let http_payload = b"POST /login HTTP/1.1\r\nHost: intranet.corp\r\nAuthorization: Basic YWRtaW46U3VwZXJTZWNyZXQxMjM=\r\n\r\n";
                        let tcp = craft_tcp(54330, 80, step as u32 * 50, 1000, 0x18, http_payload);
                        (craft_ipv4_packet([192, 168, 1, 75], [10, 0, 0, 5], 6, &tcp), None)
                    }
                    3 => {
                        // DNS Tunneling (High-Entropy query name >= 50 chars)
                        let dns = craft_dns_query("v10-a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1.tunnel.exfil-data.org");
                        let udp = craft_udp(51235, 53, &dns);
                        (craft_ipv4_packet([192, 168, 1, 80], [8, 8, 4, 4], 17, &udp), None)
                    }
                    4 | 5 => {
                        // C2 Beaconing: periodic check-ins from 192.168.1.105 -> 198.51.100.44:8443
                        // Timestamp spaced every 4 seconds
                        let beacon_ts = 1_700_000_100 + ((step / 2) * 4) as u32;
                        let tcp = craft_tcp(49152, 8443, step as u32 * 200, 500, 0x18, b"BEACON_STAGE2_POLL");
                        (craft_ipv4_packet([192, 168, 1, 105], [198, 51, 100, 44], 6, &tcp), Some((beacon_ts, "C2 Beacon Check-in [Cobalt/Mythic]")))
                    }
                    _ => {
                        // ICMP Echo request
                        let mut icmp = vec![0x08, 0x00, 0xf7, 0xff, 0x12, 0x34, 0x00, 0x01];
                        icmp.extend_from_slice(b"ping_test_payload");
                        (craft_ipv4_packet([192, 168, 1, 50], [1, 1, 1, 1], 1, &icmp), None)
                    }
                };

                let effective_ts = summary_override.map(|(ts, _)| ts).unwrap_or(ts_sec);
                let decoded = decode_packet(&packet_bytes);
                tracker.record(&decoded, effective_ts, 0);

                let (src, dst, proto, mut summary) = packet_summary(&decoded, &registry);
                if let Some((_, text)) = summary_override {
                    summary = text.into();
                }

                let _ = tx.send(LiveFeedEvent::Packet {
                    ts_sec: effective_ts,
                    src,
                    dst,
                    proto,
                    len: packet_bytes.len(),
                    summary,
                });

                for a in engine.feed(&decoded, effective_ts) {
                    let mitre = ndap_intel::mitre_for_rule(&a.rule);
                    let _ = tx.send(LiveFeedEvent::Alert {
                        ts_sec: a.ts_sec,
                        rule: a.rule,
                        severity: format!("{:?}", a.severity),
                        message: a.message,
                        mitre_id: mitre.as_ref().map(|m| m.id.clone()),
                        mitre_name: mitre.as_ref().map(|m| m.name.clone()),
                    });

                    let mut stats = live_stats.write().await;
                    stats.alerts += 1;
                }

                {
                    let mut stats = live_stats.write().await;
                    stats.packets += 1;
                    stats.conversations = tracker.conversations.len();
                }

                if step.is_multiple_of(5) {
                    let stats = live_stats.read().await;
                    let _ = tx.send(LiveFeedEvent::Stats {
                        packets: stats.packets,
                        conversations: stats.conversations,
                        alerts: stats.alerts,
                    });
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
            }
        }

        let _ = tx.send(LiveFeedEvent::Status {
            capturing: false,
            message: "Live network feed stopped".into(),
        });
    });

    Json(serde_json::json!({
        "status": "started",
        "message": "Live capture stream activated"
    }))
}

async fn capture_stop(State(state): State<AppState>) -> Json<serde_json::Value> {
    state.is_capturing.store(false, Ordering::SeqCst);
    Json(serde_json::json!({
        "status": "stopped",
        "message": "Live capture stream halted"
    }))
}

async fn capture_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = state.live_stats.read().await;
    Json(serde_json::json!({
        "capturing": state.is_capturing.load(Ordering::SeqCst),
        "packets": stats.packets,
        "conversations": stats.conversations,
        "alerts": stats.alerts,
    }))
}

// ---------------------------------------------------------------------
// Threat Intelligence & IOC Feed Endpoints
// ---------------------------------------------------------------------

async fn get_intel_sources(State(state): State<AppState>) -> Json<Vec<IocFeedSource>> {
    Json(state.ioc_mgr.get_sources())
}

async fn add_intel_source(
    State(state): State<AppState>,
    Json(source): Json<IocFeedSource>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    if !source.url.starts_with("http://") && !source.url.starts_with("https://") {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": "Only http:// and https:// feed URLs are permitted"
            })),
        ));
    }
    state.ioc_mgr.add_source(source);
    Ok(Json(serde_json::json!({ "status": "added" })))
}

async fn sync_intel(State(state): State<AppState>) -> Json<serde_json::Value> {
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let results = state.ioc_mgr.sync_all_due(now_ts);
    let stats = state.ioc_mgr.get_stats();
    Json(serde_json::json!({
        "synced_sources": results.len(),
        "stats": stats
    }))
}

async fn get_intel_stats(State(state): State<AppState>) -> Json<IocStats> {
    Json(state.ioc_mgr.get_stats())
}

// ---------------------------------------------------------------------
// Main Application Entrypoint
// ---------------------------------------------------------------------

pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/analyze", post(analyze))
        .route("/ws/live", get(ws_live_handler))
        .route("/capture/start", post(capture_start))
        .route("/capture/stop", post(capture_stop))
        .route("/capture/status", get(capture_status))
        .route("/intel/sources", get(get_intel_sources).post(add_intel_source))
        .route("/intel/sync", post(sync_intel))
        .route("/intel/stats", get(get_intel_stats))
        .fallback_service(ServeDir::new("api/static"))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel(2048);
    let ioc_store = Arc::new(RwLock::new(IocStore::new()));
    let ioc_mgr = Arc::new(IocSyncManager::new(Arc::clone(&ioc_store)));

    // Register default Threat Intel Feeds
    ioc_mgr.add_source(IocFeedSource {
        name: "local_c2_feed".into(),
        url: "https://threat-intel.internal/c2_indicators.csv".into(),
        enabled: true,
        refresh_interval_secs: 60,
        last_sync_time: None,
        last_item_count: 0,
        last_error: None,
    });
    ioc_mgr.add_source(IocFeedSource {
        name: "threatfox_recent".into(),
        url: "https://threatfox.abuse.ch/export/json/recent/".into(),
        enabled: true,
        refresh_interval_secs: 3600,
        last_sync_time: None,
        last_item_count: 0,
        last_error: None,
    });

    // Initial sync of bundled indicators
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(c2_data) = std::fs::read_to_string("crates/intel/feeds/c2_indicators.csv") {
        let _ = ioc_mgr.sync_source_data("local_c2_feed", &c2_data, now_ts);
    }

    let state = AppState {
        tx,
        is_capturing: Arc::new(AtomicBool::new(false)),
        live_stats: Arc::new(tokio::sync::RwLock::new(LiveStats::default())),
        ioc_mgr,
    };

    // Automated Background IOC Synchronizer
    let sync_mgr_bg = Arc::clone(&state.ioc_mgr);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = sync_mgr_bg.sync_all_due(now);
        }
    });

    let app = create_app(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("ndap-api listening on http://0.0.0.0:8080 (live stream on /ws/live, dashboard at /)");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health() {
        assert_eq!(health().await, "ok");
    }

    #[tokio::test]
    async fn test_capture_and_intel_lifecycle() {
        let (tx, _) = broadcast::channel(128);
        let ioc_store = Arc::new(RwLock::new(IocStore::new()));
        let ioc_mgr = Arc::new(IocSyncManager::new(Arc::clone(&ioc_store)));

        let state = AppState {
            tx,
            is_capturing: Arc::new(AtomicBool::new(false)),
            live_stats: Arc::new(tokio::sync::RwLock::new(LiveStats::default())),
            ioc_mgr: Arc::clone(&ioc_mgr),
        };

        // Check initial capture status
        let status = capture_status(State(state.clone())).await.0;
        assert_eq!(status["capturing"], false);

        // Start capture with synthetic packets
        let start_res = capture_start(
            State(state.clone()),
            Json(CaptureStartRequest {
                path: None,
                interval_ms: Some(10),
            }),
        )
        .await
        .0;
        assert_eq!(start_res["status"], "started");

        // Wait brief moment for synthetic packets to generate
        tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

        let status_running = capture_status(State(state.clone())).await.0;
        assert_eq!(status_running["capturing"], true);

        // Stop capture
        let stop_res = capture_stop(State(state.clone())).await.0;
        assert_eq!(stop_res["status"], "stopped");

        // Intel sources and stats
        let sources = get_intel_sources(State(state.clone())).await.0;
        assert_eq!(sources.len(), 0);

        let add_res = add_intel_source(
            State(state.clone()),
            Json(IocFeedSource {
                name: "test_feed".into(),
                url: "https://threats.internal/feed.csv".into(),
                enabled: true,
                refresh_interval_secs: 300,
                last_sync_time: None,
                last_item_count: 0,
                last_error: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(add_res["status"], "added");

        let sources_after = get_intel_sources(State(state.clone())).await.0;
        assert_eq!(sources_after.len(), 1);
        assert_eq!(sources_after[0].name, "test_feed");
    }
}
