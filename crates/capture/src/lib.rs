//! ndap-capture — Phase 1: Packet Engine (capture side)
//!
//! Reads classic .pcap files (magic 0xA1B2C3D4 / 0xD4C3B2A1) with zero
//! external dependencies. Live capture is defined as a trait so a real
//! backend (libpcap/AF_PACKET/npcap via a future `ndap-capture-live` crate)
//! can be dropped in without touching anything downstream.

use std::fs::File;
use std::io::{self, Read};

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
}

pub struct PcapReader {
    file: File,
    swap_endian: bool,
    // nanosecond-resolution variant (0xA1B23C4D) stores usec as nsec
    nsec: bool,
}

#[derive(Debug)]
pub enum CaptureError {
    Io(io::Error),
    BadMagic(u32),
    Truncated,
}

impl From<io::Error> for CaptureError {
    fn from(e: io::Error) -> Self {
        CaptureError::Io(e)
    }
}

impl PcapReader {
    pub fn open(path: &str) -> Result<Self, CaptureError> {
        let mut file = File::open(path)?;
        let mut hdr = [0u8; 24];
        file.read_exact(&mut hdr)?;

        let magic_le = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let (swap_endian, nsec) = match magic_le {
            0xA1B2C3D4 => (false, false), // native, usec
            0xD4C3B2A1 => (true, false),  // swapped, usec
            0xA1B23C4D => (false, true),  // native, nsec
            0x4D3CB2A1 => (true, true),   // swapped, nsec
            other => return Err(CaptureError::BadMagic(other)),
        };
        // Remaining header fields (version, thiszone, sigfigs, snaplen,
        // network/linktype) are skipped for now — Ethernet (linktype 1)
        // is assumed. TODO: branch decoders on linktype for Phase 2.
        Ok(Self { file, swap_endian, nsec })
    }

    fn read_u32(&mut self) -> Result<u32, CaptureError> {
        let mut b = [0u8; 4];
        self.file.read_exact(&mut b)?;
        Ok(if self.swap_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    /// Returns the next packet, or None at EOF.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        let ts_sec = match self.read_u32() {
            Ok(v) => v,
            Err(CaptureError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        let mut ts_usec = self.read_u32()?;
        if self.nsec {
            ts_usec /= 1000; // normalize to usec for consumers
        }
        let captured_len = self.read_u32()?;
        let original_len = self.read_u32()?;

        let mut data = vec![0u8; captured_len as usize];
        self.file
            .read_exact(&mut data)
            .map_err(|_| CaptureError::Truncated)?;

        Ok(Some(RawPacket {
            ts_sec,
            ts_usec,
            captured_len,
            original_len,
            data,
        }))
    }
}

impl Iterator for PcapReader {
    type Item = Result<RawPacket, CaptureError>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.next_packet() {
            Ok(Some(p)) => Some(Ok(p)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Backend-agnostic live capture interface. Implement this against
/// libpcap/npcap/AF_PACKET in a separate crate to plug into the same
/// downstream pipeline (protocol -> flow -> detect) with no changes there.
pub trait LiveCapture {
    fn start(&mut self, interface: &str) -> Result<(), CaptureError>;
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError>;
}

/// Placeholder so callers can compile against the trait before choosing a
/// backend. Prefer `PcapLiveCapture` for a real implementation.
pub struct UnimplementedLiveCapture;

impl LiveCapture for UnimplementedLiveCapture {
    fn start(&mut self, _interface: &str) -> Result<(), CaptureError> {
        Err(CaptureError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "live capture backend not wired yet — see LiveCapture trait",
        )))
    }
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        Ok(None)
    }
}

/// Real live-capture backend using libpcap via the `pcap` crate. Works on
/// any interface libpcap supports (Ethernet, Wi-Fi in managed mode, `any`
/// on Linux, `lo`/`lo0` for loopback). Requires elevated privileges
/// (root, or CAP_NET_RAW + CAP_NET_ADMIN on Linux) to open most interfaces.
pub struct PcapLiveCapture {
    cap: Option<pcap::Capture<pcap::Active>>,
}

impl PcapLiveCapture {
    pub fn new() -> Self {
        Self { cap: None }
    }

    /// List interface names libpcap can see, e.g. for CLI `--list-interfaces`.
    pub fn list_interfaces() -> Result<Vec<String>, CaptureError> {
        let devices = pcap::Device::list().map_err(|e| {
            CaptureError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))
        })?;
        Ok(devices.into_iter().map(|d| d.name).collect())
    }

    /// Optional BPF filter (e.g. "tcp port 443") applied after `start`.
    pub fn set_filter(&mut self, filter: &str) -> Result<(), CaptureError> {
        match self.cap.as_mut() {
            Some(c) => c
                .filter(filter, true)
                .map_err(|e| CaptureError::Io(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))),
            None => Err(CaptureError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "call start() before set_filter()",
            ))),
        }
    }
}

impl Default for PcapLiveCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveCapture for PcapLiveCapture {
    fn start(&mut self, interface: &str) -> Result<(), CaptureError> {
        let cap = pcap::Capture::from_device(interface)
            .map_err(|e| CaptureError::Io(io::Error::new(io::ErrorKind::NotFound, e.to_string())))?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000) // ms; lets next_packet() return None on idle instead of blocking forever
            .immediate_mode(true)
            .open()
            .map_err(|e| CaptureError::Io(io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())))?;
        self.cap = Some(cap);
        Ok(())
    }

    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        let cap = match self.cap.as_mut() {
            Some(c) => c,
            None => {
                return Err(CaptureError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "call start() before next_packet()",
                )))
            }
        };
        match cap.next_packet() {
            Ok(pkt) => {
                let ts_sec = pkt.header.ts.tv_sec as u32;
                let ts_usec = pkt.header.ts.tv_usec as u32;
                Ok(Some(RawPacket {
                    ts_sec,
                    ts_usec,
                    captured_len: pkt.header.caplen,
                    original_len: pkt.header.len,
                    data: pkt.data.to_vec(),
                }))
            }
            // Timeout with no packet available — not an error, just "nothing yet".
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(CaptureError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))),
        }
    }
}
