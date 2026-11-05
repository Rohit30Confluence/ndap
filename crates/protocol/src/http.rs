//! ndap-protocol — HTTP/1.x protocol parser and dissector.
//! Specifications: RFC 7230 / RFC 2616 (Hypertext Transfer Protocol).

use crate::dissector::Dissector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<HttpHeader>,
    pub body_offset: usize,
    pub body_len: usize,
}

impl HttpRequest {
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn host(&self) -> Option<&str> {
        self.get_header("Host")
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.get_header("User-Agent")
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get_header("Content-Type")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<HttpHeader>,
    pub body_offset: usize,
    pub body_len: usize,
}

impl HttpResponse {
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn server(&self) -> Option<&str> {
        self.get_header("Server")
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get_header("Content-Type")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    TooShort,
    NotHttp,
    MalformedStartLine,
    MalformedHeader,
}

const KNOWN_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Sniffs if raw bytes resemble an HTTP/1.x request or response.
pub fn is_http_payload(data: &[u8]) -> bool {
    if data.len() < 10 {
        return false;
    }
    // Check if starts with a recognized HTTP method
    for &m in KNOWN_METHODS {
        if data.starts_with(m.as_bytes()) && data.get(m.len()) == Some(&b' ') {
            return true;
        }
    }
    // Check if starts with HTTP/1. or HTTP/2.
    if data.starts_with(b"HTTP/1.") || data.starts_with(b"HTTP/2.") {
        return true;
    }
    false
}

/// Parses an HTTP/1.x message from raw payload.
pub fn parse_http(data: &[u8]) -> Result<HttpMessage, HttpError> {
    if data.len() < 10 {
        return Err(HttpError::TooShort);
    }

    // Split headers and body at \r\n\r\n (or \n\n fallback)
    let (header_bytes, body_offset) = if let Some(pos) = find_subslice(data, b"\r\n\r\n") {
        (&data[..pos], pos + 4)
    } else if let Some(pos) = find_subslice(data, b"\n\n") {
        (&data[..pos], pos + 2)
    } else {
        // May be an incomplete header or a header without body
        (data, data.len())
    };

    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => return Err(HttpError::NotHttp),
    };

    let mut lines = header_str.lines();
    let start_line = match lines.next() {
        Some(l) => l.trim_end(),
        None => return Err(HttpError::TooShort),
    };

    let body_len = data.len().saturating_sub(body_offset);

    if start_line.starts_with("HTTP/") {
        // Response: HTTP/1.1 200 OK
        let mut parts = start_line.splitn(3, ' ');
        let version = parts.next().unwrap_or("").to_string();
        let status_code_str = parts.next().ok_or(HttpError::MalformedStartLine)?;
        let status_code: u16 = status_code_str.parse().map_err(|_| HttpError::MalformedStartLine)?;
        let reason = parts.next().unwrap_or("").to_string();

        let headers = parse_headers(lines);
        Ok(HttpMessage::Response(HttpResponse {
            version,
            status_code,
            reason,
            headers,
            body_offset,
            body_len,
        }))
    } else {
        // Request: GET /path HTTP/1.1
        let mut parts = start_line.splitn(3, ' ');
        let method = parts.next().unwrap_or("").to_string();
        if !KNOWN_METHODS.iter().any(|&m| m == method) {
            return Err(HttpError::NotHttp);
        }
        let uri = parts.next().ok_or(HttpError::MalformedStartLine)?.to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();

        let headers = parse_headers(lines);
        Ok(HttpMessage::Request(HttpRequest {
            method,
            uri,
            version,
            headers,
            body_offset,
            body_len,
        }))
    }
}

fn parse_headers<'a, I: Iterator<Item = &'a str>>(lines: I) -> Vec<HttpHeader> {
    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push(HttpHeader {
                name: k.trim().to_string(),
                value: v.trim().to_string(),
            });
        }
    }
    headers
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// HTTP Protocol Dissector implementing Phase 2 `Dissector` trait.
#[derive(Default)]
pub struct HttpDissector;

impl HttpDissector {
    pub fn new() -> Self {
        Self
    }

    pub fn sniff(payload: &[u8]) -> bool {
        is_http_payload(payload)
    }
}

impl Dissector for HttpDissector {
    fn name(&self) -> &str {
        "http"
    }

    fn dissect(&self, payload: &[u8]) -> Vec<(String, String)> {
        let mut fields = Vec::new();
        match parse_http(payload) {
            Ok(HttpMessage::Request(req)) => {
                fields.push(("http.type".into(), "request".into()));
                fields.push(("http.method".into(), req.method.clone()));
                fields.push(("http.request_uri".into(), req.uri.clone()));
                fields.push(("http.version".into(), req.version.clone()));
                if let Some(host) = req.host() {
                    fields.push(("http.host".into(), host.to_string()));
                }
                if let Some(ua) = req.user_agent() {
                    fields.push(("http.user_agent".into(), ua.to_string()));
                }
                if let Some(ct) = req.content_type() {
                    fields.push(("http.content_type".into(), ct.to_string()));
                }
                if let Some(auth) = req.get_header("Authorization") {
                    // Preview auth scheme e.g. "Basic ..." or "Bearer ..."
                    let scheme = auth.split_whitespace().next().unwrap_or("present");
                    fields.push(("http.authorization".into(), scheme.to_string()));
                }
                for h in &req.headers {
                    fields.push((format!("http.header.{}", h.name.to_lowercase()), h.value.clone()));
                }
                fields.push(("http.body_len".into(), req.body_len.to_string()));
            }
            Ok(HttpMessage::Response(resp)) => {
                fields.push(("http.type".into(), "response".into()));
                fields.push(("http.version".into(), resp.version.clone()));
                fields.push(("http.status_code".into(), resp.status_code.to_string()));
                fields.push(("http.reason".into(), resp.reason.clone()));
                if let Some(server) = resp.server() {
                    fields.push(("http.server".into(), server.to_string()));
                }
                if let Some(ct) = resp.content_type() {
                    fields.push(("http.content_type".into(), ct.to_string()));
                }
                for h in &resp.headers {
                    fields.push((format!("http.header.{}", h.name.to_lowercase()), h.value.clone()));
                }
                fields.push(("http.body_len".into(), resp.body_len.to_string()));
            }
            Err(_) => {}
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_get_request() {
        let raw = b"GET /v1/status?verbose=true HTTP/1.1\r\n\
Host: api.ndap.internal\r\n\
User-Agent: curl/8.4.0\r\n\
Accept: application/json\r\n\
Authorization: Bearer secret-token-123\r\n\
\r\n";

        let msg = parse_http(raw).expect("valid HTTP GET");
        match msg {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.uri, "/v1/status?verbose=true");
                assert_eq!(req.version, "HTTP/1.1");
                assert_eq!(req.host(), Some("api.ndap.internal"));
                assert_eq!(req.user_agent(), Some("curl/8.4.0"));
                assert_eq!(req.get_header("accept"), Some("application/json"));
                assert_eq!(req.body_len, 0);
            }
            _ => panic!("expected request"),
        }

        let dissector = HttpDissector::new();
        let fields = dissector.dissect(raw);
        assert!(fields.iter().any(|(k, v)| k == "http.method" && v == "GET"));
        assert!(fields.iter().any(|(k, v)| k == "http.host" && v == "api.ndap.internal"));
        assert!(fields.iter().any(|(k, v)| k == "http.authorization" && v == "Bearer"));
    }

    #[test]
    fn test_parse_http_response() {
        let raw = b"HTTP/1.1 200 OK\r\n\
Server: nginx/1.24.0\r\n\
Content-Type: application/json\r\n\
Content-Length: 15\r\n\
\r\n\
{\"status\":\"ok\"}";

        let msg = parse_http(raw).expect("valid HTTP response");
        match msg {
            HttpMessage::Response(resp) => {
                assert_eq!(resp.version, "HTTP/1.1");
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.reason, "OK");
                assert_eq!(resp.server(), Some("nginx/1.24.0"));
                assert_eq!(resp.content_type(), Some("application/json"));
                assert_eq!(resp.body_len, 15);
            }
            _ => panic!("expected response"),
        }

        let dissector = HttpDissector::new();
        let fields = dissector.dissect(raw);
        assert!(fields.iter().any(|(k, v)| k == "http.status_code" && v == "200"));
        assert!(fields.iter().any(|(k, v)| k == "http.server" && v == "nginx/1.24.0"));
    }
}
