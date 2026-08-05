//! ndap-intel — Phase 5: Threat Intelligence.
//!
//! - `IocStore`: in-memory IOC matching, loadable from a plain CSV feed.
//! - `YaraScanner`: real YARA rule compilation + matching via `yara-x`
//!   (pure Rust, no libyara C dependency).
//! - `SigmaLiteRule`: a deliberately small field=value rule evaluator —
//!   NOT a full Sigma spec implementation (no aggregations, no near/count
//!   correlation, no full condition grammar). Real Sigma coverage would
//!   need a decision on how much of the spec to support; this covers the
//!   common "if these fields match, alert" case so rules are at least
//!   data instead of Rust code.
//! - MITRE ATT&CK technique tags attachable to alerts from ndap-detect.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

// ---------------------------------------------------------------------
// IOC store
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Ioc {
    Ip(IpAddr),
    Domain(String),
    FileHash(String), // sha256 hex
}

pub struct IocStore {
    ips: HashSet<IpAddr>,
    domains: HashSet<String>,
    hashes: HashSet<String>,
}

impl IocStore {
    pub fn new() -> Self {
        Self { ips: HashSet::new(), domains: HashSet::new(), hashes: HashSet::new() }
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

    pub fn len(&self) -> usize {
        self.ips.len() + self.domains.len() + self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Load IOCs from a plain-text CSV feed: one `type,value` pair per
    /// line, `type` in {ip, domain, hash}. Blank lines and lines starting
    /// with `#` are skipped. This is intentionally the simplest possible
    /// feed format (not STIX/TAXII or a MISP export) — those need a
    /// decision on which feed you actually want to pull from; this format
    /// is trivial to generate from any of them with a one-line script.
    ///
    /// Returns the number of IOCs loaded.
    pub fn load_from_file(&mut self, path: &str) -> Result<usize, String> {
        let contents = fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
        let mut loaded = 0;
        for (lineno, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, ',');
            let kind = parts.next().unwrap_or("").trim();
            let value = match parts.next() {
                Some(v) => v.trim(),
                None => {
                    return Err(format!("{path}:{}: expected `type,value`, got `{line}`", lineno + 1))
                }
            };
            match kind {
                "ip" => {
                    let ip: IpAddr = value
                        .parse()
                        .map_err(|_| format!("{path}:{}: invalid IP `{value}`", lineno + 1))?;
                    self.add(Ioc::Ip(ip));
                }
                "domain" => self.add(Ioc::Domain(value.to_string())),
                "hash" => self.add(Ioc::FileHash(value.to_string())),
                other => {
                    return Err(format!(
                        "{path}:{}: unknown IOC type `{other}` (expected ip, domain, or hash)",
                        lineno + 1
                    ))
                }
            }
            loaded += 1;
        }
        Ok(loaded)
    }
}

impl Default for IocStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------
// YARA matching (real, via yara-x — pure Rust, no libyara at build time)
// ---------------------------------------------------------------------

pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
}

/// Compiles a set of YARA rule sources once, then scans byte buffers
/// (e.g. reassembled TCP stream payloads, or extracted files) against
/// them repeatedly.
pub struct YaraScanner {
    rules: yara_x::Rules,
}

impl YaraScanner {
    /// Compile one or more YARA rule source strings into a scannable set.
    /// Returns a compile error message (with line info from yara-x) on
    /// bad rule syntax rather than panicking.
    pub fn compile(rule_sources: &[&str]) -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        for (i, src) in rule_sources.iter().enumerate() {
            compiler
                .add_source(*src)
                .map_err(|e| format!("rule source #{i}: {e}"))?;
        }
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Compile all `.yar`/`.yara` files in a directory (non-recursive).
    pub fn compile_from_dir(dir: &str) -> Result<Self, String> {
        let entries = fs::read_dir(dir).map_err(|e| format!("reading {dir}: {e}"))?;
        let mut sources: Vec<String> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let ext_ok = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "yar" || e == "yara")
                .unwrap_or(false);
            if ext_ok {
                sources.push(fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?);
            }
        }
        let refs: Vec<&str> = sources.iter().map(|s| s.as_str()).collect();
        Self::compile(&refs)
    }

    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = match scanner.scan(data) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        results
            .matching_rules()
            .map(|r| YaraMatch {
                rule_name: r.identifier().to_string(),
                namespace: r.namespace().to_string(),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------
// Sigma-lite: a small field=value rule evaluator, not full Sigma.
// ---------------------------------------------------------------------

/// One condition: does `field` equal `value` (case-insensitive) in the
/// event map handed to `evaluate`? All conditions in a rule are AND-ed.
#[derive(Debug, Clone)]
pub struct SigmaLiteCondition {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct SigmaLiteRule {
    pub title: String,
    pub conditions: Vec<SigmaLiteCondition>,
    pub mitre: Option<String>, // e.g. "T1071"
}

impl SigmaLiteRule {
    /// event: field name -> field value, e.g. {"dst_port": "4444", "proto": "tcp"}
    pub fn matches(&self, event: &HashMap<String, String>) -> bool {
        if self.conditions.is_empty() {
            return false;
        }
        self.conditions.iter().all(|c| {
            event
                .get(&c.field)
                .map(|v| v.eq_ignore_ascii_case(&c.value))
                .unwrap_or(false)
        })
    }
}

/// Parse a minimal rule file format (deliberately not full Sigma YAML):
/// ```text
/// title: Suspicious C2 port
/// mitre: T1071
/// field: dst_port
/// value: 4444
/// ---
/// title: ...
/// ```
/// Multiple `field:`/`value:` pairs before a rule's `---` are AND-ed.
pub fn parse_sigma_lite(source: &str) -> Result<Vec<SigmaLiteRule>, String> {
    let mut rules = Vec::new();
    for (i, block) in source.split("---").enumerate() {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }
        let mut title = None;
        let mut mitre = None;
        let mut conditions = Vec::new();
        let mut pending_field: Option<String> = None;

        for line in block.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| format!("block {i}: bad line `{line}`, expected `key: value`"))?;
            let (key, value) = (key.trim(), value.trim().to_string());
            match key {
                "title" => title = Some(value),
                "mitre" => mitre = Some(value),
                "field" => pending_field = Some(value),
                "value" => {
                    let field = pending_field
                        .take()
                        .ok_or_else(|| format!("block {i}: `value:` with no preceding `field:`"))?;
                    conditions.push(SigmaLiteCondition { field, value });
                }
                other => return Err(format!("block {i}: unknown key `{other}`")),
            }
        }
        let title = title.ok_or_else(|| format!("block {i}: missing `title:`"))?;
        rules.push(SigmaLiteRule { title, conditions, mitre });
    }
    Ok(rules)
}

// ---------------------------------------------------------------------
// MITRE ATT&CK mapping for ndap-detect's built-in rules.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MitreTechnique {
    pub id: String,   // e.g. "T1046"
    pub name: String, // e.g. "Network Service Discovery"
}

/// Static lookup from ndap-detect rule name -> MITRE technique. Extend as
/// new detection rules are added.
pub fn mitre_for_rule(rule_name: &str) -> Option<MitreTechnique> {
    match rule_name {
        "port_scan" => Some(MitreTechnique {
            id: "T1046".to_string(),
            name: "Network Service Discovery".to_string(),
        }),
        "syn_flood" => Some(MitreTechnique {
            id: "T1498".to_string(),
            name: "Network Denial of Service".to_string(),
        }),
        "arp_spoof" => Some(MitreTechnique {
            id: "T1557".to_string(),
            name: "Adversary-in-the-Middle".to_string(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_csv_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("ndap_intel_test_iocs.csv");
        std::fs::write(&path, "# comment\nip,8.8.8.8\ndomain,evil.example\nhash,deadbeef\n").unwrap();
        let mut store = IocStore::new();
        let n = store.load_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(n, 3);
        assert!(store.matches_ip(&"8.8.8.8".parse().unwrap()));
        assert!(store.matches_domain("EVIL.example"));
        assert!(store.matches_hash("DEADBEEF"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn yara_basic_match() {
        let rule = r#"
            rule contains_evil {
                strings:
                    $a = "evil-marker"
                condition:
                    $a
            }
        "#;
        let scanner = YaraScanner::compile(&[rule]).unwrap();
        let hits = scanner.scan(b"some payload with evil-marker inside");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "contains_evil");

        let no_hits = scanner.scan(b"totally benign payload");
        assert!(no_hits.is_empty());
    }

    #[test]
    fn sigma_lite_parse_and_match() {
        let src = "title: Suspicious C2 port\nmitre: T1071\nfield: dst_port\nvalue: 4444\n";
        let rules = parse_sigma_lite(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].mitre.as_deref(), Some("T1071"));

        let mut event = HashMap::new();
        event.insert("dst_port".to_string(), "4444".to_string());
        assert!(rules[0].matches(&event));

        event.insert("dst_port".to_string(), "443".to_string());
        assert!(!rules[0].matches(&event));
    }

    #[test]
    fn mitre_mapping_known_rules() {
        assert_eq!(mitre_for_rule("port_scan").unwrap().id, "T1046");
        assert!(mitre_for_rule("nonexistent_rule").is_none());
    }
}
