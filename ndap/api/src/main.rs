//! ndap-api — Phase 6 (backend slice only; no frontend yet).
//!
//! Real web UI (live packet view, protocol tree, flow graphs, timeline)
//! needs a frontend decision (React/Svelte/plain HTML+HTMX) plus
//! websocket streaming for live capture — neither is scoped here.
//! This gives you a working REST surface to build that against.

use axum::{
    extract::Json,
    routing::{get, post},
    Router,
};
use ndap_detect::DetectionEngine;
use ndap_flow::ConversationTracker;
use ndap_protocol::decode_packet;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;

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
    alerts: Vec<AlertOut>,
}

async fn health() -> &'static str {
    "ok"
}

async fn analyze(Json(req): Json<AnalyzeRequest>) -> Json<AnalyzeResponse> {
    let mut tracker = ConversationTracker::new();
    let mut engine = DetectionEngine::with_default_rules();
    let mut packets = 0u64;
    let mut alerts = Vec::new();

    match ndap_capture::PcapReader::open(&req.path) {
        Ok(reader) => {
            for raw in reader {
                let Ok(raw) = raw else { break };
                packets += 1;
                let decoded = decode_packet(&raw.data);
                tracker.record(&decoded, raw.ts_sec, raw.ts_usec);
                for a in engine.feed(&decoded, raw.ts_sec) {
                    let mitre = ndap_intel::mitre_for_rule(&a.rule);
                    alerts.push(AlertOut {
                        ts_sec: a.ts_sec,
                        rule: a.rule,
                        severity: format!("{:?}", a.severity),
                        message: a.message,
                        mitre_id: mitre.as_ref().map(|m| m.id.clone()),
                        mitre_name: mitre.as_ref().map(|m| m.name.clone()),
                    });
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

    Json(AnalyzeResponse { packets, conversations: tracker.conversations.len(), alerts })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/analyze", post(analyze))
        .fallback_service(ServeDir::new("api/static"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("ndap-api listening on http://0.0.0.0:8080  (dashboard at /)");
    axum::serve(listener, app).await.unwrap();
}
