# ndap-protocol

Protocol decoding and application layer dissector framework for NDAP.

## Features

- **Zero External Dependencies**: Decoders written directly against RFC wire specifications in pure safe Rust.
- **Layer 2 / Layer 3 / Layer 4**:
  - Ethernet II (RFC 894)
  - IPv4 (RFC 791)
  - IPv6 (RFC 8200)
  - ARP (RFC 826)
  - TCP (RFC 793) with flag helpers (`is_syn()`, `is_ack()`, `is_rst()`, `is_fin()`)
  - UDP (RFC 768)
  - ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) with echo ID/sequence extraction and human-readable type names
- **Layer 7 Dissectors**:
  - **DNS (RFC 1035)**: Query/response header flags, recursion flags, questions, answers, authorities, additionals with compression pointer loop protection.
  - **HTTP/1.x (RFC 7230)**: Request methods, URIs, versions, response status codes, reason phrases, case-insensitive headers, and body previews.
- **Protocol Registry**:
  - Dynamic registration of port-based dissectors.
  - Heuristic payload sniffing for non-standard ports.

## Usage

```rust
use ndap_protocol::{decode_packet, ProtocolRegistry, L4};

let decoded = decode_packet(&raw_packet_bytes);
let registry = ProtocolRegistry::with_builtin_dissectors();

if let Some(dissection) = decoded.dissect(&registry) {
    println!("Protocol: {}", dissection.protocol);
    for (k, v) in &dissection.fields {
        println!("  {k} = {v}");
    }
}
```
