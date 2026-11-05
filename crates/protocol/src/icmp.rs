//! ndap-protocol — ICMPv4 and ICMPv6 decoding.
//! Specifications: RFC 792 (ICMPv4) & RFC 4443 (ICMPv6).

use crate::DecodeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: [u8; 4],
}

impl IcmpHeader {
    pub fn echo_id(&self) -> u16 {
        u16::from_be_bytes([self.rest[0], self.rest[1]])
    }

    pub fn echo_seq(&self) -> u16 {
        u16::from_be_bytes([self.rest[2], self.rest[3]])
    }

    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == 8 || self.icmp_type == 128
    }

    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type == 0 || self.icmp_type == 129
    }

    pub fn type_name(&self) -> &'static str {
        match self.icmp_type {
            // ICMPv4
            0 => "Echo Reply",
            3 => "Destination Unreachable",
            4 => "Source Quench",
            5 => "Redirect",
            8 => "Echo Request",
            9 => "Router Advertisement",
            10 => "Router Solicitation",
            11 => "Time Exceeded",
            12 => "Parameter Problem",
            13 => "Timestamp",
            14 => "Timestamp Reply",
            // ICMPv6
            1 => "ICMPv6 Destination Unreachable",
            2 => "ICMPv6 Packet Too Big",
            128 => "ICMPv6 Echo Request",
            129 => "ICMPv6 Echo Reply",
            133 => "ICMPv6 Router Solicitation",
            134 => "ICMPv6 Router Advertisement",
            135 => "ICMPv6 Neighbor Solicitation",
            136 => "ICMPv6 Neighbor Advertisement",
            _ => "Unknown ICMP",
        }
    }
}

pub fn decode_icmp(data: &[u8]) -> Result<(IcmpHeader, &[u8]), DecodeError> {
    if data.len() < 8 {
        return Err(DecodeError::TooShort("icmp"));
    }
    let icmp_type = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let mut rest = [0u8; 4];
    rest.copy_from_slice(&data[4..8]);

    Ok((
        IcmpHeader {
            icmp_type,
            code,
            checksum,
            rest,
        },
        &data[8..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_icmp_echo_request() {
        let raw = [
            0x08, 0x00, // Type 8 (Echo Request), Code 0
            0x4d, 0x56, // Checksum
            0x12, 0x34, // ID: 0x1234
            0x00, 0x01, // Seq: 1
            0x61, 0x62, 0x63, 0x64, // payload "abcd"
        ];
        let (hdr, payload) = decode_icmp(&raw).expect("valid ICMP");
        assert_eq!(hdr.icmp_type, 8);
        assert_eq!(hdr.code, 0);
        assert_eq!(hdr.checksum, 0x4d56);
        assert_eq!(hdr.echo_id(), 0x1234);
        assert_eq!(hdr.echo_seq(), 1);
        assert!(hdr.is_echo_request());
        assert!(!hdr.is_echo_reply());
        assert_eq!(hdr.type_name(), "Echo Request");
        assert_eq!(payload, b"abcd");
    }

    #[test]
    fn test_decode_icmp_too_short() {
        let raw = [0x08, 0x00, 0x00];
        assert!(decode_icmp(&raw).is_err());
    }
}
