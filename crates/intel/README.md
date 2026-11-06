# ndap-intel

Threat intelligence and rule matching crate for NDAP.

## Features

- **IOC Store (`IocStore`)**:
  - In-memory lookups for IP addresses, domain names, and SHA256 file hashes.
  - Streaming feed loader parsing plain CSV (`type,value`) and JSON array formats.
- **Automated Feed Synchronization (`IocSyncManager`)**:
  - Multi-feed manager supporting remote HTTP/HTTPS feeds and local `file://` sources.
  - Interval-based synchronization scheduling with error tracking, item counts, and status reporting.
- **Sigma-Lite Rule Evaluator**:
  - Compact field=value evaluator matching packet/event attributes against Sigma-style rules without heavy external YAML engines.
- **YARA Pattern Matching**:
  - Pure-Rust YARA compiler and scanning engine via `yara-x` (no C `libyara` compilation required).
- **MITRE ATT&CK Enrichment**:
  - Maps built-in and custom detection rules to standard MITRE ATT&CK techniques (e.g. `T1046`, `T1498`, `T1557`, `T1071.004`, `T1552`).

## Usage

```rust
use ndap_intel::{Ioc, IocStore, mitre_for_rule};

let mut store = IocStore::new();
store.add(Ioc::Domain("malicious.c2.example".into()));

assert!(store.matches_domain("malicious.c2.example"));

if let Some(mitre) = mitre_for_rule("dns_tunnel") {
    println!("Technique: {} ({})", mitre.id, mitre.name);
}
```
