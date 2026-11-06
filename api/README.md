# ndap-api

REST API, WebSocket live streaming server, and web dashboard for NDAP.

## Features

- **Live WebSocket Streaming (`/ws/live`)**:
  - High-throughput broadcast channel delivering real-time decoded packet feeds, protocol classifications, and threat detection alerts directly to web browsers.
- **Capture Orchestration**:
  - `POST /capture/start`: Initiates real-time packet capture from a PCAP file or an automated synthetic traffic simulator (generating live DNS queries, HTTP transactions, ICMP messages, C2 beaconing check-ins, and DNS tunneling attacks).
  - `POST /capture/stop`: Halts the live capture stream.
  - `GET /capture/status`: Returns active capture state, total streamed packets, active flows, and alerts.
- **Threat Intelligence Feed Management**:
  - `GET /intel/sources`: Lists configured IOC feed sources with sync metrics.
  - `POST /intel/sources`: Adds or updates remote/local feed sources.
  - `POST /intel/sync`: Triggers synchronization across all feeds due for refresh.
  - `GET /intel/stats`: Returns aggregated indicator counts (IPs, domains, hashes).
- **Batch PCAP Analysis**:
  - `POST /analyze`: Performs deep wire decoding and detection analysis on uploaded/local PCAP files, returning JSON metrics and streaming events to connected WebSocket observers.
- **Embedded Web Dashboard**:
  - Zero-build Single Page Application served directly by Axum at `http://localhost:8080/`.

## Running the API Server

```bash
cargo run -p ndap-api
```

Open `http://localhost:8080/` in your browser.
