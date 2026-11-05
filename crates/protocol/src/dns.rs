//! ndap-protocol — DNS protocol parser and dissector.
//! Specification: RFC 1035 (Domain Names - Implementation and Specification).

use crate::dissector::Dissector;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn qtype_name(&self) -> &'static str {
        dns_type_name(self.qtype)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
    pub formatted_data: String,
}

impl DnsRecord {
    pub fn rtype_name(&self) -> &'static str {
        dns_type_name(self.rtype)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    TooShort,
    InvalidLabel,
    PointerLoop,
    UnexpectedEof,
}

pub fn dns_type_name(rtype: u16) -> &'static str {
    match rtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        255 => "ANY",
        _ => "OTHER",
    }
}

pub fn dns_rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NoError",
        1 => "FormErr",
        2 => "ServFail",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        6 => "YXDomain",
        7 => "YXRRSet",
        8 => "NXRRSet",
        9 => "NotAuth",
        10 => "NotZone",
        _ => "Unknown",
    }
}

pub fn dns_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        _ => "UNKNOWN",
    }
}

struct DnsCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DnsCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[allow(dead_code)]
    fn read_u8(&mut self) -> Result<u8, DnsError> {
        if self.pos >= self.data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<u16, DnsError> {
        if self.pos + 2 > self.data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, DnsError> {
        if self.pos + 4 > self.data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DnsError> {
        if self.pos + len > self.data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Parses a DNS name (handling compression pointers).
    fn read_name(&mut self) -> Result<String, DnsError> {
        let mut labels = Vec::new();
        let mut curr_pos = self.pos;
        let mut jumped = false;
        let mut jumps = 0;
        const MAX_JUMPS: usize = 10;

        loop {
            if curr_pos >= self.data.len() {
                return Err(DnsError::UnexpectedEof);
            }
            let len = self.data[curr_pos];

            if len == 0 {
                if !jumped {
                    self.pos = curr_pos + 1;
                }
                break;
            }

            // Pointer check: two high bits set (0xC0)
            if (len & 0xC0) == 0xC0 {
                if curr_pos + 1 >= self.data.len() {
                    return Err(DnsError::UnexpectedEof);
                }
                let ptr_offset = (((len & 0x3F) as usize) << 8) | (self.data[curr_pos + 1] as usize);
                if ptr_offset >= self.data.len() {
                    return Err(DnsError::InvalidLabel);
                }
                if !jumped {
                    self.pos = curr_pos + 2;
                    jumped = true;
                }
                curr_pos = ptr_offset;
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(DnsError::PointerLoop);
                }
                continue;
            }

            // Normal label
            let label_len = len as usize;
            curr_pos += 1;
            if curr_pos + label_len > self.data.len() {
                return Err(DnsError::UnexpectedEof);
            }
            let label_bytes = &self.data[curr_pos..curr_pos + label_len];
            let label_str = String::from_utf8_lossy(label_bytes).to_string();
            labels.push(label_str);
            curr_pos += label_len;

            if !jumped {
                self.pos = curr_pos;
            }
        }

        if labels.is_empty() {
            Ok(".".to_string())
        } else {
            Ok(labels.join("."))
        }
    }
}

/// Parse a raw DNS packet into a structured `DnsMessage`.
pub fn parse_dns(payload: &[u8]) -> Result<DnsMessage, DnsError> {
    if payload.len() < 12 {
        return Err(DnsError::TooShort);
    }
    let mut cursor = DnsCursor::new(payload);

    let id = cursor.read_u16()?;
    let flags = cursor.read_u16()?;
    let qdcount = cursor.read_u16()?;
    let ancount = cursor.read_u16()?;
    let nscount = cursor.read_u16()?;
    let arcount = cursor.read_u16()?;

    let is_response = (flags & 0x8000) != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let authoritative = (flags & 0x0400) != 0;
    let truncated = (flags & 0x0200) != 0;
    let recursion_desired = (flags & 0x0100) != 0;
    let recursion_available = (flags & 0x0080) != 0;
    let rcode = (flags & 0x000F) as u8;

    let header = DnsHeader {
        id,
        is_response,
        opcode,
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    };

    let mut questions = Vec::with_capacity(qdcount as usize);
    for _ in 0..qdcount {
        let name = cursor.read_name()?;
        let qtype = cursor.read_u16()?;
        let qclass = cursor.read_u16()?;
        questions.push(DnsQuestion { name, qtype, qclass });
    }

    let mut answers = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        answers.push(read_record(&mut cursor)?);
    }

    let mut authorities = Vec::with_capacity(nscount as usize);
    for _ in 0..nscount {
        authorities.push(read_record(&mut cursor)?);
    }

    let mut additionals = Vec::with_capacity(arcount as usize);
    for _ in 0..arcount {
        additionals.push(read_record(&mut cursor)?);
    }

    Ok(DnsMessage {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn read_record(cursor: &mut DnsCursor) -> Result<DnsRecord, DnsError> {
    let name = cursor.read_name()?;
    let rtype = cursor.read_u16()?;
    let rclass = cursor.read_u16()?;
    let ttl = cursor.read_u32()?;
    let rdlength = cursor.read_u16()? as usize;
    let rdata = cursor.read_bytes(rdlength)?.to_vec();

    let formatted_data = match rtype {
        1 if rdata.len() == 4 => {
            let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            ip.to_string()
        }
        28 if rdata.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&rdata);
            let ip = Ipv6Addr::from(arr);
            ip.to_string()
        }
        16 if !rdata.is_empty() => {
            // TXT records: series of <length-byte><text>
            let mut txts = Vec::new();
            let mut i = 0;
            while i < rdata.len() {
                let slen = rdata[i] as usize;
                i += 1;
                if i + slen <= rdata.len() {
                    txts.push(String::from_utf8_lossy(&rdata[i..i + slen]).to_string());
                    i += slen;
                } else {
                    break;
                }
            }
            txts.join(" ")
        }
        5 | 2 | 12 => {
            // CNAME, NS, or PTR
            let mut sub_cursor = DnsCursor::new(cursor.data);
            sub_cursor.pos = cursor.pos - rdlength;
            sub_cursor.read_name().unwrap_or_else(|_| hex_preview(&rdata))
        }
        _ => hex_preview(&rdata),
    };

    Ok(DnsRecord {
        name,
        rtype,
        rclass,
        ttl,
        data: rdata,
        formatted_data,
    })
}

fn hex_preview(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    if data.len() <= 16 {
        data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
    } else {
        let head = data[..16].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("");
        format!("{head}...({} bytes)", data.len())
    }
}

/// DNS Protocol Dissector implementing Phase 2 `Dissector` trait.
#[derive(Default)]
pub struct DnsDissector;

impl DnsDissector {
    pub fn new() -> Self {
        Self
    }

    /// Fast heuristic check if payload looks like a DNS query/response.
    pub fn sniff(payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);
        let nscount = u16::from_be_bytes([payload[8], payload[9]]);
        let arcount = u16::from_be_bytes([payload[10], payload[11]]);

        // In typical DNS traffic, questions are between 1 and 10, total records reasonable
        (1..=20).contains(&qdcount) && (ancount + nscount + arcount) < 100
    }
}

impl Dissector for DnsDissector {
    fn name(&self) -> &str {
        "dns"
    }

    fn dissect(&self, payload: &[u8]) -> Vec<(String, String)> {
        let mut fields = Vec::new();
        let msg = match parse_dns(payload) {
            Ok(m) => m,
            Err(_) => return fields,
        };

        fields.push(("dns.id".into(), format!("{:#06x}", msg.header.id)));
        fields.push((
            "dns.flags.qr".into(),
            if msg.header.is_response { "response".into() } else { "query".into() },
        ));
        fields.push(("dns.flags.opcode".into(), dns_opcode_name(msg.header.opcode).into()));
        fields.push(("dns.flags.rcode".into(), dns_rcode_name(msg.header.rcode).into()));
        fields.push(("dns.flags.rd".into(), if msg.header.recursion_desired { "1".into() } else { "0".into() }));
        fields.push(("dns.flags.ra".into(), if msg.header.recursion_available { "1".into() } else { "0".into() }));
        fields.push(("dns.count.queries".into(), msg.questions.len().to_string()));
        fields.push(("dns.count.answers".into(), msg.answers.len().to_string()));

        for q in &msg.questions {
            fields.push(("dns.qry.name".into(), q.name.clone()));
            fields.push(("dns.qry.type".into(), q.qtype_name().into()));
        }

        for a in &msg.answers {
            fields.push(("dns.resp.name".into(), a.name.clone()));
            fields.push(("dns.resp.type".into(), a.rtype_name().into()));
            fields.push(("dns.resp.ttl".into(), a.ttl.to_string()));
            fields.push(("dns.resp.data".into(), a.formatted_data.clone()));
        }

        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query() {
        // DNS query for example.com (type A, class IN)
        let raw = [
            0x12, 0x34, // ID: 0x1234
            0x01, 0x00, // Flags: Standard query, RD=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // QNAME: 7example3com0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,       // null terminator
            0x00, 0x01, // QTYPE: A (1)
            0x00, 0x01, // QCLASS: IN (1)
        ];

        let msg = parse_dns(&raw).expect("valid query");
        assert_eq!(msg.header.id, 0x1234);
        assert!(!msg.header.is_response);
        assert!(msg.header.recursion_desired);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, 1);
        assert_eq!(msg.questions[0].qtype_name(), "A");

        let dissector = DnsDissector::new();
        let fields = dissector.dissect(&raw);
        assert!(fields.iter().any(|(k, v)| k == "dns.qry.name" && v == "example.com"));
        assert!(fields.iter().any(|(k, v)| k == "dns.flags.qr" && v == "query"));
    }

    #[test]
    fn test_parse_dns_response() {
        // DNS response for example.com with answer 93.184.216.34
        let raw = [
            0x12, 0x34, // ID: 0x1234
            0x81, 0x80, // Flags: Response, RD=1, RA=1, NoError
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer: pointer to offset 12 (0xc00c)
            0xc0, 0x0c,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x01, 0x2c, // TTL: 300
            0x00, 0x04, // RDLENGTH: 4
            93, 184, 216, 34, // IP: 93.184.216.34
        ];

        let msg = parse_dns(&raw).expect("valid response");
        assert!(msg.header.is_response);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "example.com");
        assert_eq!(msg.answers[0].rtype_name(), "A");
        assert_eq!(msg.answers[0].ttl, 300);
        assert_eq!(msg.answers[0].formatted_data, "93.184.216.34");

        let dissector = DnsDissector::new();
        let fields = dissector.dissect(&raw);
        assert!(fields.iter().any(|(k, v)| k == "dns.resp.data" && v == "93.184.216.34"));
    }
}
