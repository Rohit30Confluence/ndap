# NDAP Python Plugin SDK

Extensibility SDK for writing community detection rules in Python.

## Overview

The NDAP Python SDK enables threat researchers and community developers to author detection rules in Python while preserving the high performance and memory safety of the Rust core engine.

Rules run in isolated child processes communicating with `ndap-detect` via standard JSON-lines IPC over stdin and stdout. A slow or crashing Python plugin cannot destabilize or crash the core packet engine.

## Writing a Plugin

1. Subclass `DetectionRule`.
2. Implement `on_packet(self, pkt: Packet) -> list[Alert]`.
3. Call `run_plugin()` in `__main__`.

```python
from ndap_plugin import DetectionRule, Packet, Alert, run_plugin

class SshBruteForceRule(DetectionRule):
    name = "ssh_bruteforce"

    def __init__(self, threshold: int = 10):
        self.threshold = threshold
        self.attempts = {}

    def on_packet(self, pkt: Packet) -> list[Alert]:
        if pkt.protocol == "tcp" and pkt.dst_port == 22 and pkt.flags and "SYN" in pkt.flags:
            count = self.attempts.get(pkt.src_ip, 0) + 1
            self.attempts[pkt.src_ip] = count
            if count == self.threshold:
                return [
                    Alert(
                        rule=self.name,
                        severity="medium",
                        message=f"Possible SSH brute-force from {pkt.src_ip} ({count} SYN attempts)",
                    )
                ]
        return []

if __name__ == "__main__":
    run_plugin(SshBruteForceRule())
```

## Running from Rust

In Rust (`ndap-detect`):
```rust
use ndap_detect::{DetectionEngine, PythonPluginRule};

let mut engine = DetectionEngine::new();
let python_rule = PythonPluginRule::spawn("path/to/my_rule.py")
    .expect("launch python plugin");

engine.register(Box::new(python_rule));
```
