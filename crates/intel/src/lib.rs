//! ndap-intel — Phase 5: Threat Intelligence.
//!
//! Decisions locked in (previously TODO, now implemented):
//!   - IOC format: plain JSON array or CSV (`type,value` per line) — no
//!     dependency on STIX/TAXII/MISP schemas, so any feed can be converted
//!     to this with a one-line script.
//!   - Sigma: minimal from-scratch evaluator covering `detection.selection`
//!     field-equality/contains/OR-list matching plus a boolean `condition`
//!     string (and/or/not/parens over selection names). Not full Sigma spec
//!     (no aggregations, no timeframes) — covers the common case.
//!   - YARA: real integration via the `yara` crate (needs libyara at
//!     build+runtime — documented in README).
//!   - MITRE ATT&CK: static technique tags attached to built-in detection
//!     rules (see `built_in_technique`).

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

// ---------------------------------------------------------------------
// IOC store
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Ioc {
    Ip(IpAddr),
    Domain(String),
    FileHash(String), // sha256 hex, lowercased
}

#[derive(Debug, Deserialize)]
struct IocJsonEntry {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Default)]
pub struct IocStore {
    ips: HashSet<IpAddr>,
    domains: HashSet<String>,
    hashes: HashSet<String>,
}

impl IocStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, ioc: Ioc) {
        match ioc {
            Ioc::Ip(ip) => { self.ips.insert(ip); }
            Ioc::Domain(d) => { self.domains.insert(d.to_lowercase()); }
            Ioc::FileHash(h) => { self.hashes.insert(h.to_lowercase()); }
        }
    }

    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        self.domains.contains(&domain.to_lowercase())
    }

    pub fn matches_hash(&self, hash: &str) -> bool {
        self.hashes.contains(&hash.to_lowercase())
    }

    /// Load from a JSON array: `[{"type": "ip", "value": "1.2.3.4"}, ...]`
    /// `type` is one of "ip", "domain", "hash".
    pub fn load_json(&mut self, contents: &str) -> Result<usize, String> {
        let entries: Vec<IocJsonEntry> =
            serde_json::from_str(contents).map_err(|e| e.to_string())?;
        let mut n = 0;
        for e in entries {
            match e.kind.as_str() {
                "ip" => {
                    let ip: IpAddr = e.value.parse().map_err(|_| format!("bad ip: {}", e.value))?;
                    self.add(Ioc::Ip(ip));
                    n += 1;
                }
                "domain" => { self.add(Ioc::Domain(e.value)); n += 1; }
                "hash" => { self.add(Ioc::FileHash(e.value)); n += 1; }
                other => return Err(format!("unknown ioc type: {other}")),
            }
        }
        Ok(n)
    }

    /// Load from CSV lines: `type,value` (no header, `#` comments allowed).
    pub fn load_csv(&mut self, contents: &str) -> Result<usize, String> {
        let mut n = 0;
        for (i, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, ',');
            let kind = parts.next().ok_or_else(|| format!("line {i}: missing type"))?.trim();
            let value = parts.next().ok_or_else(|| format!("line {i}: missing value"))?.trim();
            match kind {
                "ip" => {
                    let ip: IpAddr = value.parse().map_err(|_| format!("line {i}: bad ip: {value}"))?;
                    self.add(Ioc::Ip(ip));
                }
                "domain" => self.add(Ioc::Domain(value.to_string())),
                "hash" => self.add(Ioc::FileHash(value.to_string())),
                other => return Err(format!("line {i}: unknown ioc type: {other}")),
            }
            n += 1;
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------
// Sigma-lite: selection/condition subset, no aggregations/timeframes
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
enum FieldMatch {
    Equals(String),
    Contains(String),
    OneOf(Vec<String>),
}

impl FieldMatch {
    fn is_match(&self, actual: &str) -> bool {
        match self {
            FieldMatch::Equals(v) => actual == v,
            FieldMatch::Contains(v) => actual.contains(v.as_str()),
            FieldMatch::OneOf(vs) => vs.iter().any(|v| v == actual),
        }
    }
}

pub struct SigmaRule {
    pub title: String,
    selections: HashMap<String, Vec<(String, FieldMatch)>>,
    condition: String,
}

fn yaml_value_to_field_match(field: &str, value: &serde_yaml::Value) -> (String, FieldMatch) {
    let (base_field, contains) = match field.strip_suffix("|contains") {
        Some(f) => (f.to_string(), true),
        None => (field.to_string(), false),
    };
    if contains {
        let s = value.as_str().unwrap_or_default().to_string();
        return (base_field, FieldMatch::Contains(s));
    }
    if let Some(seq) = value.as_sequence() {
        let vals = seq
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        return (base_field, FieldMatch::OneOf(vals));
    }
    let s = match value {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    };
    (base_field, FieldMatch::Equals(s))
}

impl SigmaRule {
    /// Parse a Sigma-lite YAML rule:
    /// ```yaml
    /// title: Suspiciously long DNS query
    /// detection:
    ///   selection:
    ///     dst_port: 53
    ///     protocol: udp
    ///   condition: selection
    /// ```
    pub fn parse(yaml_src: &str) -> Result<Self, String> {
        let doc: serde_yaml::Value = serde_yaml::from_str(yaml_src).map_err(|e| e.to_string())?;
        let title = doc.get("title").and_then(|v| v.as_str()).unwrap_or("untitled").to_string();
        let detection = doc.get("detection").ok_or("missing `detection` block")?;
        let mapping = detection.as_mapping().ok_or("`detection` must be a mapping")?;

        let mut condition = String::new();
        let mut selections = HashMap::new();

        for (k, v) in mapping {
            let key = k.as_str().unwrap_or_default();
            if key == "condition" {
                condition = v.as_str().unwrap_or_default().to_string();
                continue;
            }
            let sel_mapping = v.as_mapping().ok_or_else(|| format!("selection '{key}' must be a mapping"))?;
            let mut fields = Vec::new();
            for (fk, fv) in sel_mapping {
                let field_name = fk.as_str().unwrap_or_default();
                fields.push(yaml_value_to_field_match(field_name, fv));
            }
            selections.insert(key.to_string(), fields);
        }

        if condition.is_empty() {
            return Err("missing `condition`".to_string());
        }
        Ok(Self { title, selections, condition })
    }

    /// Evaluate against a flat event (field name -> stringified value).
    pub fn matches(&self, event: &HashMap<String, String>) -> bool {
        eval_condition(&self.condition, &self.selections, event)
    }
}

fn selection_matches(fields: &[(String, FieldMatch)], event: &HashMap<String, String>) -> bool {
    fields.iter().all(|(field, m)| {
        event.get(field).map(|actual| m.is_match(actual)).unwrap_or(false)
    })
}

/// Tiny recursive-descent boolean evaluator for `and` / `or` / `not` / `()`
/// over selection-name identifiers.
fn eval_condition(
    expr: &str,
    selections: &HashMap<String, Vec<(String, FieldMatch)>>,
    event: &HashMap<String, String>,
) -> bool {
    let tokens: Vec<String> = expr
        .replace('(', " ( ")
        .replace(')', " ) ")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let mut pos = 0;
    parse_or(&tokens, &mut pos, selections, event)
}

fn parse_or(
    tokens: &[String],
    pos: &mut usize,
    selections: &HashMap<String, Vec<(String, FieldMatch)>>,
    event: &HashMap<String, String>,
) -> bool {
    let mut result = parse_and(tokens, pos, selections, event);
    while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("or") {
        *pos += 1;
        let rhs = parse_and(tokens, pos, selections, event);
        result = result || rhs;
    }
    result
}

fn parse_and(
    tokens: &[String],
    pos: &mut usize,
    selections: &HashMap<String, Vec<(String, FieldMatch)>>,
    event: &HashMap<String, String>,
) -> bool {
    let mut result = parse_not(tokens, pos, selections, event);
    while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("and") {
        *pos += 1;
        let rhs = parse_not(tokens, pos, selections, event);
        result = result && rhs;
    }
    result
}

fn parse_not(
    tokens: &[String],
    pos: &mut usize,
    selections: &HashMap<String, Vec<(String, FieldMatch)>>,
    event: &HashMap<String, String>,
) -> bool {
    if *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("not") {
        *pos += 1;
        return !parse_not(tokens, pos, selections, event);
    }
    parse_atom(tokens, pos, selections, event)
}

fn parse_atom(
    tokens: &[String],
    pos: &mut usize,
    selections: &HashMap<String, Vec<(String, FieldMatch)>>,
    event: &HashMap<String, String>,
) -> bool {
    if *pos >= tokens.len() {
        return false;
    }
    if tokens[*pos] == "(" {
        *pos += 1;
        let result = parse_or(tokens, pos, selections, event);
        if *pos < tokens.len() && tokens[*pos] == ")" {
            *pos += 1;
        }
        return result;
    }
    let name = &tokens[*pos];
    *pos += 1;
    selections
        .get(name.as_str())
        .map(|fields| selection_matches(fields, event))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------
// YARA — real integration (needs libyara at build + runtime)
// ---------------------------------------------------------------------

pub struct YaraScanner {
    rules: yara::Rules,
}

impl YaraScanner {
    /// Compile YARA rule source (one or more `rule { ... }` blocks).
    pub fn compile(rule_source: &str) -> Result<Self, String> {
        let compiler = yara::Compiler::new().map_err(|e| e.to_string())?;
        let compiler = compiler.add_rules_str(rule_source).map_err(|e| e.to_string())?;
        let rules = compiler.compile_rules().map_err(|e| e.to_string())?;
        Ok(Self { rules })
    }

    /// Scan a byte buffer (e.g. a reassembled TCP stream or UDP payload).
    /// Returns matched rule names. `timeout_secs` bounds worst-case scans.
    pub fn scan(&self, data: &[u8], timeout_secs: i32) -> Result<Vec<String>, String> {
        let matches = self
            .rules
            .scan_mem(data, timeout_secs)
            .map_err(|e| e.to_string())?;
        Ok(matches.into_iter().map(|m| m.identifier.to_string()).collect())
    }
}

// ---------------------------------------------------------------------
// MITRE ATT&CK tags
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
}

/// Static mapping for the built-in ndap-detect rules. Extend this as more
/// rules are added; Sigma/YARA/plugin-authored rules can attach their own.
pub fn built_in_technique(rule_name: &str) -> Option<MitreTechnique> {
    let (id, name) = match rule_name {
        "port_scan" => ("T1046", "Network Service Discovery"),
        "syn_flood" => ("T1499", "Endpoint Denial of Service"),
        "arp_spoof" => ("T1557", "Adversary-in-the-Middle"),
        _ => return None,
    };
    Some(MitreTechnique { id: id.to_string(), name: name.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_store_json_and_csv() {
        let mut store = IocStore::new();
        let n = store.load_json(r#"[{"type":"ip","value":"1.2.3.4"},{"type":"domain","value":"evil.example"}]"#).unwrap();
        assert_eq!(n, 2);
        assert!(store.matches_ip(&"1.2.3.4".parse().unwrap()));
        assert!(store.matches_domain("EVIL.example"));

        let n2 = store.load_csv("ip,9.9.9.9\n# comment\ndomain,bad.test\n").unwrap();
        assert_eq!(n2, 2);
        assert!(store.matches_ip(&"9.9.9.9".parse().unwrap()));
    }

    #[test]
    fn sigma_lite_matches() {
        let yaml = r#"
title: Long DNS query
detection:
  selection:
    protocol: udp
    dst_port: 53
  condition: selection
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        let mut event = HashMap::new();
        event.insert("protocol".to_string(), "udp".to_string());
        event.insert("dst_port".to_string(), "53".to_string());
        assert!(rule.matches(&event));

        event.insert("dst_port".to_string(), "80".to_string());
        assert!(!rule.matches(&event));
    }

    #[test]
    fn sigma_lite_and_or_not() {
        let yaml = r#"
title: combo
detection:
  a:
    x: "1"
  b:
    y: "2"
  condition: a and not b
"#;
        let rule = SigmaRule::parse(yaml).unwrap();
        let mut event = HashMap::new();
        event.insert("x".to_string(), "1".to_string());
        assert!(rule.matches(&event)); // a true, b false -> a and not b = true

        event.insert("y".to_string(), "2".to_string());
        assert!(!rule.matches(&event)); // b now true -> not b = false
    }

    #[test]
    fn yara_real_scan() {
        let rule_src = r#"
rule test_rule {
    strings:
        $a = "malicious-payload-marker"
    condition:
        $a
}
"#;
        let scanner = YaraScanner::compile(rule_src).unwrap();
        let hits = scanner.scan(b"some data with malicious-payload-marker inside", 5).unwrap();
        assert_eq!(hits, vec!["test_rule"]);

        let no_hits = scanner.scan(b"totally benign data", 5).unwrap();
        assert!(no_hits.is_empty());
    }

    #[test]
    fn mitre_tags() {
        assert_eq!(built_in_technique("port_scan").unwrap().id, "T1046");
        assert!(built_in_technique("nonexistent").is_none());
    }
}
