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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

// ---------------------------------------------------------------------
// IOC store
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ioc {
    Ip(IpAddr),
    Domain(String),
    FileHash(String), // sha256 hex
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocStats {
    pub total: usize,
    pub ips: usize,
    pub domains: usize,
    pub hashes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocFeedSource {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub refresh_interval_secs: u64,
    pub last_sync_time: Option<u64>,
    pub last_item_count: usize,
    pub last_error: Option<String>,
}

#[derive(Clone)]
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

    pub fn stats(&self) -> IocStats {
        IocStats {
            total: self.len(),
            ips: self.ips.len(),
            domains: self.domains.len(),
            hashes: self.hashes.len(),
        }
    }

    /// Load IOCs from a plain-text CSV feed string: one `type,value` per line.
    pub fn load_from_str(&mut self, contents: &str) -> Result<usize, String> {
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
                    return Err(format!("line {}: invalid CSV format, expected `type,value`", lineno + 1))
                }
            };
            match kind {
                "ip" => {
                    let ip: IpAddr = value
                        .parse()
                        .map_err(|_| format!("line {}: invalid IP format", lineno + 1))?;
                    self.add(Ioc::Ip(ip));
                }
                "domain" => self.add(Ioc::Domain(value.to_string())),
                "hash" => self.add(Ioc::FileHash(value.to_string())),
                _ => {
                    return Err(format!(
                        "line {}: unknown IOC type (expected ip, domain, or hash)",
                        lineno + 1
                    ))
                }
            }
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Load IOCs from JSON: accepts an array of {"type": "...", "value": "..."} objects.
    pub fn load_from_json(&mut self, json_str: &str) -> Result<usize, String> {
        #[derive(Deserialize)]
        struct RawIocItem {
            #[serde(rename = "type")]
            kind: String,
            value: String,
        }

        let items: Vec<RawIocItem> = serde_json::from_str(json_str)
            .map_err(|e| format!("parsing IOC JSON: {e}"))?;

        let mut loaded = 0;
        for item in items {
            match item.kind.to_lowercase().as_str() {
                "ip" => {
                    if let Ok(ip) = item.value.parse::<IpAddr>() {
                        self.add(Ioc::Ip(ip));
                        loaded += 1;
                    }
                }
                "domain" => {
                    self.add(Ioc::Domain(item.value));
                    loaded += 1;
                }
                "hash" => {
                    self.add(Ioc::FileHash(item.value));
                    loaded += 1;
                }
                _ => {}
            }
        }
        Ok(loaded)
    }

    /// Load IOCs from a local CSV file.
    pub fn load_from_file(&mut self, path: &str) -> Result<usize, String> {
        let contents = fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
        self.load_from_str(&contents)
    }
}

impl Default for IocStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Automated IOC Feed Synchronizer managing multiple remote/local feed sources.
#[derive(Clone)]
pub struct IocSyncManager {
    store: Arc<RwLock<IocStore>>,
    sources: Arc<RwLock<Vec<IocFeedSource>>>,
}

impl IocSyncManager {
    pub fn new(store: Arc<RwLock<IocStore>>) -> Self {
        Self {
            store,
            sources: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn add_source(&self, source: IocFeedSource) {
        if let Ok(mut sources) = self.sources.write() {
            sources.retain(|s| s.name != source.name);
            sources.push(source);
        }
    }

    pub fn get_sources(&self) -> Vec<IocFeedSource> {
        self.sources.read().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn get_stats(&self) -> IocStats {
        self.store.read().map(|s| s.stats()).unwrap_or_default()
    }

    /// Synchronizes a specific feed source using provided raw data string.
    pub fn sync_source_data(&self, name: &str, data: &str, now_ts: u64) -> Result<usize, String> {
        let mut store = self.store.write().map_err(|_| "failed to lock IOC store".to_string())?;
        let count = if data.trim_start().starts_with('[') {
            store.load_from_json(data)?
        } else {
            store.load_from_str(data)?
        };

        if let Ok(mut sources) = self.sources.write() {
            if let Some(src) = sources.iter_mut().find(|s| s.name == name) {
                src.last_sync_time = Some(now_ts);
                src.last_item_count = count;
                src.last_error = None;
            }
        }
        Ok(count)
    }

    /// Returns a list of enabled sources that are due for refresh.
    pub fn sources_due_for_sync(&self, now_ts: u64) -> Vec<IocFeedSource> {
        let sources = match self.sources.read() {
            Ok(s) => s.clone(),
            Err(_) => return Vec::new(),
        };

        sources
            .into_iter()
            .filter(|s| {
                if !s.enabled {
                    return false;
                }
                match s.last_sync_time {
                    None => true,
                    Some(last) => now_ts.saturating_sub(last) >= s.refresh_interval_secs,
                }
            })
            .collect()
    }

    /// Fetches IOC feed content from a remote URL (strictly restricted to `http://` and `https://`).
    pub fn fetch_url(url: &str) -> Result<String, String> {
        let trimmed = url.trim();
        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            return Err("rejected URL scheme: only http:// and https:// feeds are permitted".to_string());
        }
        if trimmed.starts_with('-') {
            return Err("invalid URL: argument injection attempt detected".to_string());
        }

        let output = std::process::Command::new("curl")
            .args(["-sSL", "--max-time", "15", "--", trimmed])
            .output()
            .map_err(|_| "failed to execute HTTP fetcher process".to_string())?;

        if !output.status.success() {
            return Err(format!("fetch request failed with exit status {:?}", output.status.code()));
        }

        String::from_utf8(output.stdout)
            .map_err(|_| "feed content contains invalid UTF-8 data".to_string())
    }

    /// Fetches and synchronizes a specific named feed source.
    pub fn sync_source(&self, name: &str, now_ts: u64) -> Result<usize, String> {
        let source = {
            let sources = self.sources.read().map_err(|_| "failed to read sources".to_string())?;
            sources.iter().find(|s| s.name == name).cloned()
        };

        let Some(source) = source else {
            return Err(format!("feed source '{name}' not found"));
        };

        match Self::fetch_url(&source.url) {
            Ok(content) => {
                let res = self.sync_source_data(name, &content, now_ts);
                if let Err(ref e) = res {
                    if let Ok(mut sources) = self.sources.write() {
                        if let Some(s) = sources.iter_mut().find(|s| s.name == name) {
                            s.last_error = Some(e.clone());
                        }
                    }
                }
                res
            }
            Err(e) => {
                if let Ok(mut sources) = self.sources.write() {
                    if let Some(s) = sources.iter_mut().find(|s| s.name == name) {
                        s.last_error = Some(e.clone());
                    }
                }
                Err(e)
            }
        }
    }

    /// Automatically synchronizes all sources that are currently due for refresh.
    pub fn sync_all_due(&self, now_ts: u64) -> Vec<(String, Result<usize, String>)> {
        let due = self.sources_due_for_sync(now_ts);
        let mut results = Vec::new();
        for src in due {
            let res = self.sync_source(&src.name, now_ts);
            results.push((src.name, res));
        }
        results
    }
}

// ---------------------------------------------------------------------
// YARA matching (real, via yara-x — pure Rust, no libyara at build time).
// Gated behind the `yara` feature: yara-x pulls a large dependency tree
// and needs a current Rust toolchain (edition 2024, rustc 1.85+), so it's
// opt-in rather than forced on every consumer of this crate. Build with
// `cargo build --features yara` to include it.
// ---------------------------------------------------------------------

#[cfg(feature = "yara")]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
}

/// Compiles a set of YARA rule sources once, then scans byte buffers
/// (e.g. reassembled TCP stream payloads, or extracted files) against
/// them repeatedly.
#[cfg(feature = "yara")]
pub struct YaraScanner {
    rules: yara_x::Rules,
}

#[cfg(feature = "yara")]
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
        "dns_tunnel" => Some(MitreTechnique {
            id: "T1071.004".to_string(),
            name: "Application Layer Protocol: DNS".to_string(),
        }),
        "cleartext_credentials" => Some(MitreTechnique {
            id: "T1552".to_string(),
            name: "Unsecured Credentials".to_string(),
        }),
        "c2_beaconing" => Some(MitreTechnique {
            id: "T1071".to_string(),
            name: "Standard Application Layer Protocol".to_string(),
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
    #[cfg(feature = "yara")]
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
    fn ioc_json_and_sync_manager() {
        let store = Arc::new(RwLock::new(IocStore::new()));
        let sync_mgr = IocSyncManager::new(Arc::clone(&store));

        let source = IocFeedSource {
            name: "otx_alienvault".into(),
            url: "https://otx.alienvault.com/api/v1/indicators/export".into(),
            enabled: true,
            refresh_interval_secs: 3600,
            last_sync_time: None,
            last_item_count: 0,
            last_error: None,
        };
        sync_mgr.add_source(source);

        let json_feed = r#"[
            {"type": "ip", "value": "198.51.100.99"},
            {"type": "domain", "value": "c2-malicious.org"},
            {"type": "hash", "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
        ]"#;

        let loaded = sync_mgr.sync_source_data("otx_alienvault", json_feed, 1000).unwrap();
        assert_eq!(loaded, 3);

        let stats = sync_mgr.get_stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.ips, 1);
        assert_eq!(stats.domains, 1);
        assert_eq!(stats.hashes, 1);

        let sources = sync_mgr.get_sources();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].last_item_count, 3);
        assert_eq!(sources[0].last_sync_time, Some(1000));

        let due = sync_mgr.sources_due_for_sync(2000); // 1000s elapsed, interval 3600s
        assert!(due.is_empty());

        let due = sync_mgr.sources_due_for_sync(5000); // 4000s elapsed >= 3600s
        assert_eq!(due.len(), 1);

        // Verify URL restriction & argument injection defense
        assert!(IocSyncManager::fetch_url("file:///etc/passwd").is_err());
        assert!(IocSyncManager::fetch_url("/etc/shadow").is_err());
        assert!(IocSyncManager::fetch_url("-o /tmp/evil").is_err());
        assert!(IocSyncManager::fetch_url("ftp://malicious.org").is_err());

        // Test direct synchronization via sync_source_data
        let csv_feed = "ip,203.0.113.42\ndomain,evil-c2.com\n";
        let loaded = sync_mgr.sync_source_data("otx_alienvault", csv_feed, 6000).unwrap();
        assert_eq!(loaded, 2);

        let store_guard = store.read().unwrap();
        assert!(store_guard.matches_ip(&"203.0.113.42".parse().unwrap()));
        assert!(store_guard.matches_domain("evil-c2.com"));
    }

    #[test]
    fn mitre_mapping_known_rules() {
        assert_eq!(mitre_for_rule("port_scan").unwrap().id, "T1046");
        assert_eq!(mitre_for_rule("dns_tunnel").unwrap().id, "T1071.004");
        assert_eq!(mitre_for_rule("cleartext_credentials").unwrap().id, "T1552");
        assert_eq!(mitre_for_rule("c2_beaconing").unwrap().id, "T1071");
        assert!(mitre_for_rule("nonexistent_rule").is_none());
    }
}
