# ndap-flow

Conversation tracking and TCP stream reassembly engine for NDAP.

## Features

- **Direction-Independent 5-Tuple**: Canonical hash key mapping both directions of a session (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) to the same conversation bucket.
- **Session Metrics**: Tracks total packet counts, cumulative byte volumes, and first/last seen timestamps.
- **TCP Stream Reassembly**:
  - `TcpStream` state machine tracking sequence numbers per direction.
  - In-order payload concatenation.
  - Out-of-order segment buffering and automatic contiguous segment draining.

## Usage

```rust
use ndap_flow::ConversationTracker;
use ndap_protocol::decode_packet;

let mut tracker = ConversationTracker::new();
tracker.record(&decoded_packet, ts_sec, ts_usec);

println!("Active conversations: {}", tracker.conversations.len());
```
