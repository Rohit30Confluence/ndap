"""
NDAP Python Plugin SDK (stub).

Goal: let community detection packs be written in Python, matching the
"Core Engine -> Plugin SDK -> Community Plugins -> Detection Packs" model
from the original proposal, without touching the Rust core.

Real wiring TODO (needs a decision from you):
  - PyO3-embedded interpreter inside ndap-detect, vs.
  - out-of-process plugins that read JSON packets over a Unix socket/stdin
    from the Rust core (simpler, slower, easier to sandbox)

This file defines the contract either approach would expose to plugin
authors, so plugin code doesn't have to change once the backend is picked.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Packet:
    ts_sec: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "tcp" | "udp" | "arp" | ...
    flags: Optional[str] = None
    payload: bytes = b""


@dataclass
class Alert:
    rule: str
    severity: str  # "low" | "medium" | "high" | "critical"
    message: str


class DetectionRule:
    """Subclass this to write a plugin detection rule in Python."""

    name: str = "unnamed_rule"

    def on_packet(self, pkt: Packet) -> list[Alert]:
        raise NotImplementedError


# Example plugin a community author might write:
class ExampleDnsTunnelRule(DetectionRule):
    name = "dns_tunnel_example"

    def __init__(self, query_len_threshold: int = 60):
        self.query_len_threshold = query_len_threshold

    def on_packet(self, pkt: Packet) -> list[Alert]:
        if pkt.protocol == "udp" and pkt.dst_port == 53 and len(pkt.payload) > self.query_len_threshold:
            return [Alert(
                rule=self.name,
                severity="medium",
                message=f"Unusually long DNS query ({len(pkt.payload)} bytes) to {pkt.dst_ip}",
            )]
        return []
