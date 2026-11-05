"""
NDAP Python Plugin SDK.

Allows community detection rules to be written in Python and executed
out-of-process by the Rust core engine via JSON-lines over stdin/stdout.
"""

from dataclasses import dataclass
import json
import sys
from typing import List, Optional


@dataclass
class Packet:
    ts_sec: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "tcp" | "udp" | "icmp" | "arp" | ...
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

    def on_packet(self, pkt: Packet) -> List[Alert]:
        raise NotImplementedError


class ExampleDnsTunnelRule(DetectionRule):
    """Example plugin rule: detects unusually long DNS queries."""

    name = "dns_tunnel_example"

    def __init__(self, query_len_threshold: int = 60):
        self.query_len_threshold = query_len_threshold

    def on_packet(self, pkt: Packet) -> List[Alert]:
        if pkt.protocol == "udp" and pkt.dst_port == 53 and len(pkt.payload) > self.query_len_threshold:
            return [
                Alert(
                    rule=self.name,
                    severity="high",
                    message=f"Unusually long DNS query ({len(pkt.payload)} bytes) to {pkt.dst_ip}",
                )
            ]
        return []


def run_plugin(rule: DetectionRule):
    """
    Main loop for running a Python detection rule over JSON-lines IPC.
    Reads packet events from stdin, evaluates them using `rule`, and
    emits JSON-encoded alerts to stdout.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            payload_hex = data.get("payload_hex", "")
            payload = bytes.fromhex(payload_hex) if payload_hex else b""
            pkt = Packet(
                ts_sec=data.get("ts_sec", 0),
                src_ip=data.get("src_ip", ""),
                dst_ip=data.get("dst_ip", ""),
                src_port=data.get("src_port", 0),
                dst_port=data.get("dst_port", 0),
                protocol=data.get("protocol", ""),
                flags=data.get("flags"),
                payload=payload,
            )
            alerts = rule.on_packet(pkt)
            out = {
                "alerts": [
                    {"rule": a.rule, "severity": a.severity, "message": a.message}
                    for a in alerts
                ]
            }
        except Exception as e:
            out = {"alerts": [], "error": str(e)}

        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_plugin(ExampleDnsTunnelRule())
