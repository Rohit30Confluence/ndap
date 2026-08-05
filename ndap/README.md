# NDAP — Network Detection & Analysis Platform

Collapsed build: all six phases from the original roadmap scaffolded in one pass.
Rust workspace, zero external deps in the core crates (only the REST API pulls in
axum/tokio). No Wireshark code copied — decoders were written from the wire
formats (RFC 791/793/768, ARP, classic pcap file format).

## Status by phase

| Phase | Crate | Status |
|---|---|---|
| 1. Packet Engine | `ndap-capture`, `ndap-protocol` | **Working** — pcap file parser, Ethernet/IPv4/IPv6/ARP/TCP/UDP decode |
| 2. Protocol Framework | `ndap-protocol` | **Working core, stub extensibility** — `Dissector` trait + `ProtocolRegistry`; `PluginLoader` is a no-op |
| 3. Flow Engine | `ndap-flow` | **Working** — 5-tuple conversation tracking, TCP reassembly (in-order + basic out-of-order buffering, no SACK yet) |
| 4. Detection Engine | `ndap-detect` | **Working** — port scan, SYN flood, ARP spoof rules fire on real packet streams. DNS tunneling / beaconing / lateral movement rules not yet written (need traffic samples or a spec) |
| 5. Threat Intelligence | `ndap-intel` | **Interfaces only** — IOC store works in-memory; feed loader, Sigma evaluator, YARA matching all need a decision from you (see TODOs in the crate) |
| 6. Web UI | `ndap-api` | **Backend stub only** — `/health`, `/analyze` (POST a pcap path, get back alerts + conversation count). No frontend, no websocket live stream yet |

Plugin extensibility (Python) is a stub SDK at `plugins/python-sdk/ndap_plugin.py`
defining the contract; not wired into the Rust core yet (needs a PyO3-vs-IPC
decision — see comments in that file).

## Build & run

```bash
cd ndap
cargo build --release
./target/release/ndap path/to/capture.pcap
```

API:
```bash
cargo run -p ndap-api
curl -X POST localhost:8080/analyze -H 'content-type: application/json' \
  -d '{"path": "/path/to/capture.pcap"}'
```

## What's deliberately NOT done yet (needs your input, not guesswork)

1. **Live capture backend** — `LiveCapture` trait exists in `ndap-capture` but
   has no libpcap/npcap/AF_PACKET implementation. Needs root/CAP_NET_RAW and a
   platform decision (Linux-only first, or cross-platform via a pcap binding).
2. **Threat intel feeds** — IOC format, Sigma rule source, YARA integration
   all blocked on which feeds/formats you actually want.
3. **Frontend** — no UI framework chosen yet.
4. **Python plugin execution** — SDK contract defined, runtime not wired.

Everything else (decoders, flow tracking, the three detection rules, the API
skeleton) runs end-to-end today against a real pcap file.
