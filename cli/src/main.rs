use ndap_capture::{LiveCapture, PcapLiveCapture, PcapReader, RawPacket};
use ndap_detect::DetectionEngine;
use ndap_flow::ConversationTracker;
use ndap_protocol::{decode_packet, ProtocolRegistry, L3, L4};
use std::collections::HashMap;
use std::env;
use std::process::ExitCode;

enum Mode {
    File(String, bool),
    Live(String, bool),
    ListInterfaces,
}

fn parse_args(args: &[String]) -> Result<Mode, String> {
    if args.len() == 2 && (args[1] == "--list-interfaces" || args[1] == "-D") {
        return Ok(Mode::ListInterfaces);
    }

    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
    let mut non_flag_args: Vec<String> = args
        .iter()
        .skip(1)
        .filter(|a| *a != "-v" && *a != "--verbose")
        .cloned()
        .collect();

    if non_flag_args.len() == 2 && non_flag_args[0] == "-i" {
        return Ok(Mode::Live(non_flag_args.remove(1), verbose));
    }

    if non_flag_args.len() == 1 {
        return Ok(Mode::File(non_flag_args.remove(0), verbose));
    }

    Err("usage: ndap [-v] <file.pcap>  |  ndap [-v] -i <interface>  |  ndap --list-interfaces".to_string())
}

/// Shared pipeline: decode -> track flow -> run detection rules -> print.
/// Returns (packet_count, alert_count).
fn process(
    raw: RawPacket,
    tracker: &mut ConversationTracker,
    engine: &mut DetectionEngine,
    registry: &ProtocolRegistry,
    protocols: &mut HashMap<String, u64>,
    verbose: bool,
) -> u64 {
    let decoded = decode_packet(&raw.data);
    tracker.record(&decoded, raw.ts_sec, raw.ts_usec);

    // Track protocol stats
    match &decoded.l3 {
        Some(L3::Arp { .. }) => { *protocols.entry("ARP".into()).or_default() += 1; }
        Some(L3::Ipv4(_)) => { *protocols.entry("IPv4".into()).or_default() += 1; }
        Some(L3::Ipv6(_)) => { *protocols.entry("IPv6".into()).or_default() += 1; }
        _ => {}
    }
    match &decoded.l4 {
        L4::Tcp(_) => { *protocols.entry("TCP".into()).or_default() += 1; }
        L4::Udp(_) => { *protocols.entry("UDP".into()).or_default() += 1; }
        L4::Icmp(_) => { *protocols.entry("ICMP".into()).or_default() += 1; }
        _ => {}
    }

    if let Some(dissection) = decoded.dissect(registry) {
        *protocols.entry(dissection.protocol.to_uppercase()).or_default() += 1;
        if verbose {
            match dissection.protocol.as_str() {
                "dns" => {
                    let qry = dissection.get_field("dns.qry.name").unwrap_or("-");
                    let qtype = dissection.get_field("dns.qry.type").unwrap_or("A");
                    let qr = dissection.get_field("dns.flags.qr").unwrap_or("query");
                    println!("[{:>8}] [DNS] {} {} ({})", raw.ts_sec, qr, qry, qtype);
                }
                "http" => {
                    if let Some(method) = dissection.get_field("http.method") {
                        let uri = dissection.get_field("http.request_uri").unwrap_or("/");
                        let host = dissection.get_field("http.host").unwrap_or("");
                        println!("[{:>8}] [HTTP] {} {} {}", raw.ts_sec, method, host, uri);
                    } else if let Some(code) = dissection.get_field("http.status_code") {
                        let phrase = dissection.get_field("http.reason").unwrap_or("");
                        println!("[{:>8}] [HTTP] HTTP {} {}", raw.ts_sec, code, phrase);
                    }
                }
                "icmp" => {
                    let tname = dissection.get_field("icmp.type_name").unwrap_or("ICMP");
                    println!("[{:>8}] [ICMP] {}", raw.ts_sec, tname);
                }
                _ => {}
            }
        }
    }

    let mut fired = 0;
    for alert in engine.feed(&decoded, raw.ts_sec) {
        fired += 1;
        println!(
            "[{:>8}] {:?} {} :: {}",
            alert.ts_sec, alert.severity, alert.rule, alert.message
        );
    }
    fired
}

fn print_summary(packet_count: u64, conv_count: usize, alert_count: u64, protocols: &HashMap<String, u64>) {
    println!("---");
    println!("packets decoded : {packet_count}");
    println!("conversations   : {conv_count}");
    println!("alerts fired    : {alert_count}");
    if !protocols.is_empty() {
        let mut sorted: Vec<_> = protocols.iter().collect();
        sorted.sort_by_key(|(p, count)| (std::cmp::Reverse(**count), (*p).clone()));
        let proto_line = sorted
            .iter()
            .map(|(p, c)| format!("{p}={c}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("protocols       : {proto_line}");
    }
}

fn run_file(path: &str, verbose: bool) -> ExitCode {
    let reader = match PcapReader::open(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to open {path}: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let mut tracker = ConversationTracker::new();
    let mut engine = DetectionEngine::with_default_rules();
    let registry = ProtocolRegistry::with_builtin_dissectors();
    let mut protocols: HashMap<String, u64> = HashMap::new();
    let mut packet_count: u64 = 0;
    let mut alert_count: u64 = 0;

    for raw in reader {
        let raw = match raw {
            Ok(r) => r,
            Err(e) => {
                eprintln!("read error: {e:?}");
                break;
            }
        };
        packet_count += 1;
        alert_count += process(raw, &mut tracker, &mut engine, &registry, &mut protocols, verbose);
    }

    print_summary(packet_count, tracker.conversations.len(), alert_count, &protocols);
    ExitCode::SUCCESS
}

fn run_live(interface: &str, verbose: bool) -> ExitCode {
    let mut cap = PcapLiveCapture::new();
    if let Err(e) = cap.start(interface) {
        eprintln!("failed to open interface '{interface}': {e:?}");
        eprintln!("hint: live capture needs root or CAP_NET_RAW/CAP_NET_ADMIN.");
        eprintln!("run `ndap --list-interfaces` to see what libpcap can see.");
        return ExitCode::FAILURE;
    }

    println!("capturing on {interface} — Ctrl+C to stop");
    let mut tracker = ConversationTracker::new();
    let mut engine = DetectionEngine::with_default_rules();
    let registry = ProtocolRegistry::with_builtin_dissectors();
    let mut protocols: HashMap<String, u64> = HashMap::new();
    let mut packet_count: u64 = 0;
    let mut alert_count: u64 = 0;

    loop {
        match cap.next_packet() {
            Ok(Some(raw)) => {
                packet_count += 1;
                alert_count += process(raw, &mut tracker, &mut engine, &registry, &mut protocols, verbose);
            }
            Ok(None) => continue,
            Err(e) => {
                eprintln!("capture error: {e:?}");
                break;
            }
        }
    }

    print_summary(packet_count, tracker.conversations.len(), alert_count, &protocols);
    ExitCode::SUCCESS
}

fn run_list_interfaces() -> ExitCode {
    match PcapLiveCapture::list_interfaces() {
        Ok(names) => {
            if names.is_empty() {
                println!("(no interfaces visible to libpcap — try running as root)");
            }
            for name in names {
                println!("{name}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to list interfaces: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match parse_args(&args) {
        Ok(Mode::File(path, verbose)) => run_file(&path, verbose),
        Ok(Mode::Live(iface, verbose)) => run_live(&iface, verbose),
        Ok(Mode::ListInterfaces) => run_list_interfaces(),
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}
