# NDAP — Network Detection & Analysis Platform

> A modular, extensible Network Detection & Analysis Platform written in Rust for packet analysis, flow reconstruction, threat detection, threat intelligence, and future live monitoring.

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

---

# Overview

NDAP is a modern, modular network analysis platform implemented in Rust.

It provides:

- Packet parsing
- Protocol decoding
- Flow tracking
- TCP reassembly
- Detection engine
- Threat intelligence
- YARA scanning
- REST API
- Web dashboard
- Python plugin SDK

The architecture is crate-based, making every subsystem independent and easily extendable.

---

# Architecture

```
                +----------------+
                | Packet Source  |
                | PCAP / Live    |
                +-------+--------+
                        |
                        v
                +----------------+
                | Capture Engine |
                +-------+--------+
                        |
                        v
                +----------------+
                | Protocol Layer |
                +-------+--------+
                        |
                        v
                +----------------+
                | Flow Engine    |
                +-------+--------+
                        |
        +---------------+----------------+
        |                                |
        v                                v
+---------------+                +----------------+
| Detection     |                | Threat Intel   |
| Engine        |                | IOC/YARA       |
+-------+-------+                +-------+--------+
        |                                |
        +---------------+----------------+
                        |
                        v
                +----------------+
                | REST API       |
                +-------+--------+
                        |
                        v
                +----------------+
                | Dashboard      |
                +----------------+
```

---

# Workspace Layout

```
ndap/
│
├── api/
│
├── cli/
│
├── crates/
│   ├── capture/
│   ├── protocol/
│   ├── flow/
│   ├── detect/
│   └── intel/
│
├── plugins/
│   └── python-sdk/
│
└── Cargo.toml
```

---

# Features

## Packet Capture

Supports:

- Classic PCAP
- Big-endian PCAP
- Nanosecond PCAP

---

## Protocol Decoding

Implemented:

- Ethernet II
- IPv4
- IPv6
- TCP
- UDP
- ARP

Written directly from protocol specifications (RFCs).

---

## Flow Engine

Implements:

- 5-tuple tracking
- Conversation tracking
- TCP stream reassembly
- Out-of-order buffering

Current limitation:

- No TCP SACK support

---

## Detection Engine

Current detections:

| Rule | MITRE ATT&CK |
|------|---------------|
| Port Scan | T1046 |
| SYN Flood | T1499 |
| ARP Spoof | T1557 |

---

## Threat Intelligence

### IOC Store

Supported formats

- JSON
- CSV

### Sigma-lite

Supports

- selection
- and
- or
- not

Not yet implemented

- timeframe
- count()
- aggregations

### YARA

Native libyara integration.

---

## REST API

Endpoints

```
GET /
GET /health
POST /analyze
```

---

## Dashboard

Built with

- htmx
- Chart.js

No frontend build system required.

---

## Python Plugin SDK

Architecture

```
Rust Core
    │
JSON Lines
    │
stdin/stdout
    │
Python Plugin
```

Plugins execute outside the Rust process.

---

# Current Status

| Component | Status |
|------------|--------|
| Packet Engine | ✅ Complete |
| Protocol Parser | ✅ Complete |
| Flow Engine | ✅ Complete |
| TCP Reassembly | ✅ Complete |
| Detection Engine | ✅ Complete |
| IOC Engine | ✅ Complete |
| Sigma-lite | ✅ Complete |
| YARA | ✅ Complete |
| REST API | ✅ Complete |
| Dashboard | ✅ Complete |
| Python SDK | ✅ Complete |
| Live Capture | ✅ Basic |
| Dynamic Plugins | 🚧 Planned |
| WebSocket Streaming | 🚧 Planned |

---

# Installation

## Ubuntu

Install dependencies

```bash
sudo apt update

sudo apt install \
    clang \
    libclang-dev \
    libpcap-dev \
    libyara-dev \
    python3 \
    pkg-config
```

Clone

```bash
git clone https://github.com/Rohit30Confluence/ndap.git

cd ndap
```

Build

```bash
cargo build --release
```

Run tests

```bash
cargo test
```

---

# Android (Termux)

Verified on

- Android AArch64
- Rust 1.96
- Cargo 1.96

Install

```bash
pkg update

pkg install \
    git \
    rust \
    clang \
    python \
    pkg-config \
    yara \
    yara-static
```

Required before compiling

```bash
export BINDGEN_EXTRA_CLANG_ARGS="-I$PREFIX/include"
```

Build

```bash
cargo build
```

Test

```bash
cargo test
```

---

# Usage

Analyze a PCAP

```bash
cargo run -p ndap-cli -- capture.pcap
```

Start API

```bash
cargo run -p ndap-api
```

Open

```
http://127.0.0.1:8080
```

---

# Verification

## Ubuntu 24.04

```
cargo build --workspace
PASS
```

```
cargo test -p ndap-intel
5 passed
```

```
cargo test -p ndap-detect
1 passed
```

```
cargo run -p ndap-cli test.pcap

Decoded packets successfully

Port Scan detected

SYN Flood detected
```

---

## Android (Termux)

```
cargo build
PASS
```

```
cargo test

PASS

ndap_detect
1 passed

ndap_intel
5 passed

All workspace tests passed.
```

---

# Roadmap

- Dynamic protocol plugins
- Live packet streaming
- WebSocket dashboard
- Full Sigma engine
- STIX/TAXII support
- MISP integration
- Zeek log import
- Suricata rule support
- Additional protocol dissectors
- Performance optimization

---

# Limitations

Current limitations

- Dynamic dissector loading
- Live WebSocket updates
- Sigma aggregations
- IOC feed synchronization
- TCP SACK reassembly

---

# Tech Stack

| Category | Technology |
|-----------|------------|
| Language | Rust |
| API | Axum |
| Async | Tokio |
| Capture | libpcap |
| Threat Intel | YARA |
| Dashboard | htmx + Chart.js |
| Plugin SDK | Python |
| Serialization | Serde |
| Protocol Parsing | Native Rust |

---

# Contributing

```bash
git checkout -b feature/my-feature

cargo fmt

cargo clippy

cargo test
```

Submit a Pull Request after all tests pass.

---

# License

MIT License

---

# Credits

- RFC 791
- RFC 793
- RFC 768
- RFC 826
- libpcap
- YARA Project
- Rust Community

NDAP does **not** copy Wireshark source code. Protocol decoding has been implemented independently from publicly available protocol specifications.