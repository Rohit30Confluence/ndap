"""
NDAP plugin runner — the counterpart to ndap-detect's `PyPluginRule`.

Invoked by the Rust core as:
    python3 -u plugin_runner.py <plugin_path.py> <ClassName>

Protocol (line-delimited JSON, must stay in lockstep with plugin.rs):
  stdin  : one JSON object per line, matching `PyPacket` in plugin.rs
           {"ts_sec": .., "src_ip": .., "dst_ip": .., "src_port": ..,
            "dst_port": .., "protocol": .., "flags": .. | null,
            "payload_hex": ".."}
  stdout : one JSON array per line (possibly empty), matching `PyAlertWire`
           [{"rule": .., "severity": .., "message": ..}, ...]

Every stdin line must get exactly one stdout line back, or the Rust side
blocks waiting for it — this is a synchronous request/response protocol,
not a stream.
"""

import sys
import json
import importlib.util

from ndap_plugin import Packet, DetectionRule  # noqa: F401 (re-exported for plugin authors)


def load_plugin_class(plugin_path: str, class_name: str):
    spec = importlib.util.spec_from_file_location("user_plugin", plugin_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, class_name)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: plugin_runner.py <plugin_path.py> <ClassName>", file=sys.stderr)
        return 2

    plugin_path, class_name = sys.argv[1], sys.argv[2]
    try:
        cls = load_plugin_class(plugin_path, class_name)
        rule = cls()
    except Exception as e:  # noqa: BLE001 — must not crash silently, stderr goes to the parent's terminal
        print(f"[plugin_runner] failed to load {class_name} from {plugin_path}: {e}", file=sys.stderr)
        return 1

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            print("[]", flush=True)
            continue
        try:
            data = json.loads(raw_line)
            pkt = Packet(
                ts_sec=data["ts_sec"],
                src_ip=data["src_ip"],
                dst_ip=data["dst_ip"],
                src_port=data["src_port"],
                dst_port=data["dst_port"],
                protocol=data["protocol"],
                flags=data.get("flags"),
                payload=bytes.fromhex(data.get("payload_hex", "")),
            )
            alerts = rule.on_packet(pkt) or []
            out = [{"rule": a.rule, "severity": a.severity, "message": a.message} for a in alerts]
            print(json.dumps(out), flush=True)
        except Exception as e:  # noqa: BLE001 — one bad packet must not kill the whole plugin process
            print(f"[plugin_runner] error processing packet: {e}", file=sys.stderr)
            print("[]", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
