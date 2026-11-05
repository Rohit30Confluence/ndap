# ndap-capture

Packet capture subsystem for NDAP.

## Features

- **PCAP File Reader**: Reads classic `.pcap` files with zero external dependencies.
  - Supports native and byte-swapped (big-endian / little-endian) captures.
  - Supports microsecond (`0xA1B2C3D4`) and nanosecond (`0xA1B23C4D`) timestamps.
  - Streaming iterator over raw packets (`Iterator<Item = Result<RawPacket, CaptureError>>`).
- **Live Capture Backend**:
  - `LiveCapture` trait defining the capture interface.
  - `PcapLiveCapture`: Real cross-platform capture engine utilizing `libpcap` on Linux/macOS and `npcap` on Windows.
  - Device enumeration (`list_interfaces()`).
  - BPF filter compilation and application (`set_filter("tcp port 80")`).

## Usage

```rust
use ndap_capture::PcapReader;

let reader = PcapReader::open("capture.pcap").expect("open pcap");
for pkt in reader {
    let raw = pkt.expect("valid packet");
    println!("Captured packet: len={}, ts={}", raw.captured_len, raw.ts_sec);
}
```
