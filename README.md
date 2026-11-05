# NDAP — Network Detection & Analysis Platform

> A modular, extensible Network Detection & Analysis Platform written in Rust for packet decoding, conversation flow tracking, rule-based threat detection, threat intelligence, and out-of-process Python plugin extensibility.

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Android-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-17%2F17%20Passed-brightgreen)
![Zero Deps Core](https://img.shields.io/badge/Core%20Deps-Zero-success)

---

## Overview

NDAP is a modern, modular network analysis and intrusion detection platform implemented from the wire up in pure Rust. Unlike tools that depend on heavy legacy C codebases, NDAP decodes protocol wire formats directly from RFC specifications with zero external dependencies in its core crates.

### Key Capabilities
- **Capture & Parsing**: Reads classic, nanosecond, big-endian, and little-endian `.pcap` files; supports cross-platform live capture via `libpcap`/`npcap`.
- **Wire Decoders**: Ethernet, IPv4, IPv6, ARP, TCP, UDP, and ICMPv4/v6.
- **Protocol Dissectors**: Layer 7 application dissectors for DNS (RFC 1035) and HTTP/1.x (RFC 7230) with heuristic sniffing on non-standard ports.
- **Flow Engine**: 5-tuple canonical conversation tracking, session metrics, and TCP stream reassembly with out-of-order segment buffering.
- **Detection Engine**: Built-in MITRE ATT&CK mapped detection rules for Port Scans, SYN Floods, ARP Spoofing, DNS Tunneling (Shannon entropy + length), and Cleartext Credentials (HTTP Basic Auth & parameter exposure).
- **Python Plugin SDK**: Isolated out-of-process execution for community detection rules communicating over JSON-lines IPC.
- **Threat Intelligence**: In-memory IOC store (IP, domain, hash), Sigma-lite rule evaluator, and pure-Rust YARA scanning (`yara-x`).
- **REST API & Dashboard**: Embedded Axum web service delivering analysis endpoints and a responsive, zero-build web dashboard.

---

## Architecture

```
                       +-----------------------+
                       |     Packet Source     |
                       |  PCAP File / Live Net |
                       +-----------+-----------+
                                   |
                                   v
                       +-----------------------+
                       |      ndap-capture     |
                       |  Classic/Nano PCAP    |
                       +-----------+-----------+
                                   |
                                   v
                       +-----------------------+
                       |     ndap-protocol     |
                       | Wire Decoders + L7    |
                       | DNS, HTTP, ICMP, ARP  |
                       +-----------+-----------+
                                   |
                                   v
                       +-----------------------+
                       |       ndap-flow       |
                       | 5-Tuple Conversations |
                       | TCP Stream Reassembly |
                       +-----+-----------+-----+
                             |           |
             +---------------+           +---------------+
             |                                           |
             v                                           v
+-------------------------+                 +-------------------------+
|       ndap-detect       |                 |        ndap-intel       |
| Built-in Rules          |                 | IOC Store (IP/Domain/H) |
| PortScan, SYNFlood, ARP |                 | Sigma-Lite Evaluator    |
| DNSTunnel, Cleartext    |                 | YARA Scanner (yara-x)   |
+------------+------------+                 +------------+------------+
             |                                           |
             |      JSON-lines IPC (stdin/stdout)        |
             +--------------------+                      |
             |                    |                      |
             v                    v                      |
+-------------------------+       |                      |
|    Python Plugin SDK    |       |                      |
|  plugins/python-sdk/    |       |                      |
+-------------------------+       |                      |
             |                    |                      |
             +--------------------+----------------------+
                                  |
                                  v
                      +-----------------------+
                      |        ndap-api       |
                      | Axum REST Engine      |
                      | /health, /analyze     |
                      +-----------+-----------+
                                  |
                                  v
                      +-----------------------+
                      |     Web Dashboard     |
                      | Single-Page UI        |
                      +-----------------------+
```

---

## Workspace Layout

```
ndap/
├── Cargo.toml                  # Workspace manifest
├── README.md                   # Project documentation
├── .gitignore                  # Git ignore rules
├── cli/                        # ndap CLI binary
│   ├── Cargo.toml
│   └── src/main.rs             # CLI entrypoint with live dissection
├── api/                        # ndap-api REST service & Web UI
│   ├── Cargo.toml
│   ├── src/main.rs             # Axum HTTP routes & analysis handler
│   └── static/
│       └── index.html          # Embedded dashboard
├── crates/
│   ├── capture/                # PCAP file reading & live capture traits
│   ├── protocol/               # Wire decoders & L7 dissectors (DNS, HTTP, ICMP)
│   ├── flow/                   # 5-tuple tracking & TCP reassembly
│   ├── detect/                 # Threat detection engine & Python IPC runner
│   └── intel/                  # IOC matching, Sigma-lite & YARA
├── plugins/
│   └── python-sdk/             # Python plugin SDK & sample detection rule
└── docs/
    └── index.html              # GitHub Pages documentation site
```

---

## Core Components

### 1. Packet Engine (`ndap-capture`, `ndap-protocol`)
- Zero external dependencies in core protocol decoding.
- Full support for RFC 791 (IPv4), RFC 8200 (IPv6), RFC 793 (TCP), RFC 768 (UDP), RFC 826 (ARP), RFC 792 (ICMPv4), and RFC 4443 (ICMPv6).
- Big-endian and nanosecond timestamp resolution handling in `.pcap` files.

### 2. Application Protocol Dissectors (`ndap-protocol`)
- **DNS (RFC 1035)**: Full wire parser with loop-safe label compression handling (`MAX_JUMPS = 10`), query type resolution (A, AAAA, CNAME, TXT, NS, PTR, SOA, MX), and response formatting.
- **HTTP/1.x (RFC 7230)**: Request and response parser extracting methods, URIs, status codes, and case-insensitive headers.
- **ICMP (RFC 792 / RFC 4443)**: Decodes echo request/reply IDs, sequence numbers, and type descriptions.
- **`ProtocolRegistry`**: Extensible registry mapping ports to dissectors with heuristic payload sniffing for non-standard ports.

### 3. Flow Engine (`ndap-flow`)
- Direction-independent canonical 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
- Tracks conversation statistics (packet count, byte volume, first/last seen timestamps).
- State-machine TCP stream reassembly handling in-order segments and out-of-order buffering.

### 4. Detection Engine (`ndap-detect`)
All detection rules produce standardized alerts enriched with severity levels and MITRE ATT&CK techniques:

| Rule Name | Target Threat | Severity | MITRE Technique | Description |
|---|---|---|---|---|
| `port_scan` | Reconnaissance | Medium | **T1046** | Sliding-window scan detection across distinct destination ports |
| `syn_flood` | Denial of Service | High | **T1498** | High-frequency SYN bursts without matching ACKs |
| `arp_spoof` | Man-in-the-Middle | Critical | **T1557** | Detects multiple MAC addresses claiming a single IP address |
| `dns_tunnel` | Command & Control / Exfiltration | High | **T1071.004** | Shannon entropy ($H \ge 3.6$) and query length ($\ge 50$) analysis |
| `cleartext_credentials` | Credential Access | High | **T1552** | Sniffs unencrypted HTTP Basic Auth, query tokens, and body parameters |

### 5. Out-of-Process Python Plugin SDK (`plugins/python-sdk`)
Write community detection rules in Python without modifying the Rust core:
```python
from ndap_plugin import DetectionRule, Packet, Alert, run_plugin

class SshBruteForceRule(DetectionRule):
    name = "ssh_bruteforce"

    def on_packet(self, pkt: Packet) -> list[Alert]:
        if pkt.protocol == "tcp" and pkt.dst_port == 22:
            # Custom detection logic
            ...
        return []

if __name__ == "__main__":
    run_plugin(SshBruteForceRule())
```
Executed safely by `PythonPluginRule` in `ndap-detect` over standard JSON-lines IPC.

### 6. Threat Intelligence (`ndap-intel`)
- **IOC Store**: In-memory hash set matching for IP addresses, domains, and SHA256 file hashes loadable from plain CSV or JSON feeds.
- **Sigma-Lite**: Evaluates YAML field-value rules against event maps.
- **YARA**: Real compilation and scanning against byte buffers via `yara-x`.
- **MITRE Mapping**: Static and dynamic lookups mapping rule alerts to ATT&CK tactics and IDs.

---

## Installation & Build

### System Dependencies

#### Debian / Ubuntu / Kali
```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev libclang-dev clang python3
```

#### macOS (Homebrew)
```bash
brew install libpcap
```

### Compiling NDAP

Clone and build the entire workspace with Cargo:
```bash
git clone https://github.com/Rohit30Confluence/ndap.git
cd ndap

# Build release binaries
cargo build --release

# Run full test suite (17 tests)
cargo test
```

---

## Usage

### 1. CLI Analysis (`ndap`)

Analyze a PCAP file:
```bash
./target/release/ndap traffic.pcap
```

Analyze with **verbose live protocol dissection** (`[DNS]`, `[HTTP]`, `[ICMP]`):
```bash
./target/release/ndap -v traffic.pcap
```

Example Output:
```text
[     100] [ICMP] Echo Request
[     101] [DNS] query google.com (A)
[     101] [DNS] response google.com (A)
[     102] [HTTP] GET example.org /api/v1/metrics
[     102] [HTTP] HTTP 200 OK
[     102] High dns_tunnel :: Possible DNS tunneling/exfiltration query `a8f3b9c1d4...attacker.net`: query length (58) and high entropy (4.16)
[     103] High cleartext_credentials :: HTTP Basic Authentication transmitted unencrypted to internal.finance.corp (URI: /admin/dashboard)
[     104] Medium port_scan :: 10.0.0.99 touched 15 distinct ports on 192.168.1.1 in 10s (possible port scan)
---
packets decoded : 19
conversations   : 19
alerts fired    : 3
protocols       : IPv4=19, TCP=16, DNS=2, ICMP=2, UDP=2, HTTP=1
```

Live capture on an interface (requires root or `CAP_NET_RAW`):
```bash
# List available network interfaces
./target/release/ndap --list-interfaces

# Capture live packets on eth0
sudo ./target/release/ndap -i eth0
```

### 2. Web API & Dashboard (`ndap-api`)

Start the REST API server:
```bash
cargo run -p ndap-api
```
The server listens on `http://0.0.0.0:8080`.

- **Web Dashboard**: Open [http://localhost:8080](http://localhost:8080) in your browser.
- **Health Check**:
  ```bash
  curl http://localhost:8080/health
  ```
- **Analyze PCAP Endpoint**:
  ```bash
  curl -X POST http://localhost:8080/analyze \
    -H "Content-Type: application/json" \
    -d '{"path": "/absolute/path/to/capture.pcap"}'
  ```

---

## Verification & Tests

NDAP includes unit tests across all crates covering wire decoders, dissectors, detection algorithms, and Python IPC:

```bash
cargo test
```

Verification output:
```text
running 9 tests (ndap-protocol) ... ok
running 5 tests (ndap-detect) ... ok
running 3 tests (ndap-intel) ... ok

test result: ok. 17 passed; 0 failed; 0 ignored
```

Linter verification:
```bash
cargo clippy --workspace -- -D warnings
```

---

## Roadmap

- [x] PCAP file reading & wire decoders (Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP)
- [x] L7 Application Dissectors (DNS RFC 1035, HTTP/1.x RFC 7230)
- [x] 5-tuple flow engine and TCP stream reassembly
- [x] Detection rules (Port Scan, SYN Flood, ARP Spoof, DNS Tunneling, Cleartext Credentials)
- [x] MITRE ATT&CK integration
- [x] Out-of-process Python plugin execution runner
- [x] Web dashboard with protocol distribution breakdown
- [ ] Live WebSocket streaming for real-time dashboard packet feeds
- [ ] C2 Beaconing detection (periodicity and jitter clustering)
- [ ] Automated remote IOC feed synchronization

---

## License

This project is licensed under the [MIT License](LICENSE).
