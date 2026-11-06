# ndap-detect

Intrusion detection engine and rule framework for NDAP.

## Features

- **Stateful Rule Engine**: Feeds decoded packets into stateful detection rules, emitting typed `Alert` instances.
- **Built-in Detection Rules**:
  - `PortScanRule`: Detects reconnaissance across distinct destination ports in a configurable time window (MITRE `T1046`).
  - `SynFloodRule`: Identifies SYN flood DoS attacks (MITRE `T1498`).
  - `ArpSpoofRule`: Flags multiple MAC addresses claiming the same IP (MITRE `T1557`).
  - `DnsTunnelRule`: Calculates Shannon entropy ($H \ge 3.6$) and query length ($\ge 50$) to uncover DNS tunneling and data exfiltration (MITRE `T1071.004`).
  - `CleartextCredentialRule`: Inspects HTTP requests for plaintext Basic Auth headers, sensitive URL query tokens, and POST bodies (MITRE `T1552`).
  - `BeaconingRule`: Detects periodic C2 beaconing (Cobalt Strike, Mythic, etc.) via inter-arrival time deltas $\Delta t$, calculating mean $\mu$, standard deviation $\sigma$, and jitter Coefficient of Variation ($CV = \frac{\sigma}{\mu} \le 0.30$) (MITRE `T1071`).
- **Python Plugin IPC Runner**:
  - `PythonPluginRule`: Runs community detection rules out-of-process via standard JSON-lines over stdin/stdout, maintaining core engine isolation.

## Usage

```rust
use ndap_detect::DetectionEngine;
use ndap_protocol::decode_packet;

let mut engine = DetectionEngine::with_default_rules();

for alert in engine.feed(&decoded_packet, timestamp_sec) {
    println!("[{:?}] {}: {}", alert.severity, alert.rule, alert.message);
}
```
