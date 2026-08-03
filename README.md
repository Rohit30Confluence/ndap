NDAP — Network Detection & Analysis Platform

«A modular, extensible network detection and analysis platform written in Rust, designed for offline packet analysis, flow reconstruction, threat detection, threat intelligence integration, and future live capture support.»

---

Overview

NDAP is built as a collection of independent Rust crates that work together to provide a modern network analysis pipeline.

The project currently implements:

- Offline PCAP parsing
- Ethernet / IPv4 / IPv6 decoding
- TCP / UDP / ARP protocol parsing
- Flow reconstruction
- TCP stream reassembly
- Detection engine with MITRE ATT&CK mappings
- IOC matching
- Sigma-lite rule evaluation
- Real YARA scanning
- REST API
- Browser dashboard
- Python plugin SDK

The codebase is designed to remain modular so additional protocol dissectors, detection engines, plugins, and frontend capabilities can be added without changing the core architecture.

---

Project Structure

ndap/
├── api/
├── cli/
├── crates/
│   ├── capture/
│   ├── protocol/
│   ├── flow/
│   ├── detect/
│   └── intel/
├── plugins/
│   └── python-sdk/
└── Cargo.toml

---

Current Implementation Status

Phase| Component| Status
Packet Capture| ndap-capture| ✅ Complete
Protocol Parsing| ndap-protocol| ✅ Complete
Flow Tracking| ndap-flow| ✅ Complete
TCP Reassembly| ndap-flow| ✅ Complete
Detection Engine| ndap-detect| ✅ Complete
IOC Matching| ndap-intel| ✅ Complete
Sigma-lite| ndap-intel| ✅ Complete
YARA Integration| ndap-intel| ✅ Complete
REST API| ndap-api| ✅ Complete
Dashboard| ndap-api| ✅ Complete
Python Plugin SDK| plugins/python-sdk| ✅ Complete
Live Capture| ndap-capture| ✅ Basic
Dynamic Protocol Plugins| Planned| 🚧
Live Dashboard Streaming| Planned| 🚧

---

Features

Packet Engine

Supports:

- Classic PCAP
- Big-endian PCAP
- Nanosecond PCAP

Protocols:

- Ethernet II
- IPv4
- IPv6
- TCP
- UDP
- ARP

Protocol decoding is implemented directly from protocol specifications rather than copying Wireshark code.

---

Flow Engine

Implements:

- 5-tuple flow tracking
- Conversation management
- TCP stream reconstruction
- Out-of-order packet buffering

Current limitation:

- No TCP SACK support yet.

---

Detection Engine

Implemented detections include:

- Port Scan
- SYN Flood
- ARP Spoofing

Every detection includes MITRE ATT&CK mappings.

Example:

Detection| MITRE
Port Scan| T1046
SYN Flood| T1499
ARP Spoof| T1557

---

Threat Intelligence

Supports:

IOC Store

Input formats

- JSON
- CSV

Sigma-lite

Supports

- selection
- and
- or
- not

Currently unsupported

- count()
- timeframe
- aggregations

YARA

Uses the native YARA engine through libyara.

---

REST API

Current endpoints:

GET /
GET /health
POST /analyze

---

Dashboard

Single-file dashboard built using:

- htmx
- Chart.js

No Node.js build system is required.

---

Python Plugin SDK

Plugins execute outside the Rust process.

Communication:

Rust
   │
JSON Lines
   │
stdin/stdout
   │
Python Plugin

This design prevents plugin crashes from affecting the Rust core.

---

Building

Ubuntu / Debian

Install dependencies

sudo apt update

sudo apt install \
    clang \
    libclang-dev \
    libpcap-dev \
    libyara-dev \
    python3 \
    pkg-config

Build

cargo build --release

Run tests

cargo test

---

Building on Termux (Android)

Verified on:

- Android (AArch64)
- Rust 1.96
- Cargo 1.96
- Termux packages

Install dependencies

pkg update

pkg install \
    git \
    rust \
    clang \
    python \
    pkg-config \
    yara \
    yara-static

Before building, export the include path required by bindgen:

export BINDGEN_EXTRA_CLANG_ARGS="-I$PREFIX/include"

Then build:

cargo build

Run tests:

cargo test

This environment has been successfully verified.

---

Running

CLI

cargo run -p ndap-cli -- capture.pcap

API

cargo run -p ndap-api

Then open

http://127.0.0.1:8080

---

Verification

Ubuntu

Verified on

- Ubuntu 24.04
- Rust 1.75
- libpcap
- libyara
- libclang

Results

cargo build --workspace
PASS

cargo test -p ndap-intel
5 passed

cargo test -p ndap-detect
1 passed

cargo run -p ndap-cli test.pcap

Decoded packets successfully
Detection rules fired correctly

---

Termux (Android)

Verified on

- Android AArch64
- Rust 1.96
- Cargo 1.96

Environment

export BINDGEN_EXTRA_CLANG_ARGS="-I$PREFIX/include"

Results

cargo build
PASS

cargo test
PASS

ndap_detect
1 passed

ndap_intel
5 passed

All workspace tests
PASS

The only additional requirement on Termux is exporting the include path so "bindgen" can locate "yara.h".

---

Current Limitations

Not yet implemented:

- Dynamic protocol dissector loading
- Live WebSocket dashboard
- Sigma aggregations
- Automated IOC feed synchronization
- SACK-aware TCP reassembly

---

Roadmap

- Dynamic dissector plugins
- Live capture integrated with API
- WebSocket dashboard
- Full Sigma implementation
- STIX/TAXII support
- MISP integration
- Suricata rule compatibility
- Zeek log import
- Additional protocol dissectors
- Detection performance optimizations

---

License

Choose an appropriate open-source license before the first stable release.

---

Acknowledgements

Protocol implementations are based on publicly documented protocol specifications (RFCs) and original implementations.

No Wireshark source code has been copied into this project.