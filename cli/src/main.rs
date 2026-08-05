use ndap_capture::{LiveCapture, PcapLiveCapture, PcapReader, RawPacket};
use ndap_detect::DetectionEngine;
use ndap_flow::ConversationTracker;
use ndap_protocol::decode_packet;
use std::env;
use std::process::ExitCode;

enum Mode {
    File(String),
    Live(String),
    ListInterfaces,
}

fn parse_args(args: &[String]) -> Result<Mode, String> {
    if args.len() == 2 && (args[1] == "--list-interfaces" || args[1] == "-D") {
        return Ok(Mode::ListInterfaces);
    }
    if args.len() == 3 && args[1] == "-i" {
        return Ok(Mode::Live(args[2].clone()));
    }
    if args.len() == 2 {
        return Ok(Mode::File(args[1].clone()));
    }
    Err("usage: ndap <file.pcap>  |  ndap -i <interface>  |  ndap --list-interfaces".to_string())
}

/// Shared pipeline: decode -> track flow -> run detection rules -> print.
/// Returns (packet_count, alert_count).
fn process(
    raw: RawPacket,
    tracker: &mut ConversationTracker,
    engine: &mut DetectionEngine,
) -> u64 {
    let decoded = decode_packet(&raw.data);
    tracker.record(&decoded, raw.ts_sec, raw.ts_usec);

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

fn run_file(path: &str) -> ExitCode {
    let reader = match PcapReader::open(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to open {path}: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let mut tracker = ConversationTracker::new();
    let mut engine = DetectionEngine::with_default_rules();
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
        alert_count += process(raw, &mut tracker, &mut engine);
    }

    println!("---");
    println!("packets decoded : {packet_count}");
    println!("conversations   : {}", tracker.conversations.len());
    println!("alerts fired    : {alert_count}");
    ExitCode::SUCCESS
}

fn run_live(interface: &str) -> ExitCode {
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
    let mut packet_count: u64 = 0;
    let mut alert_count: u64 = 0;

    loop {
        match cap.next_packet() {
            Ok(Some(raw)) => {
                packet_count += 1;
                alert_count += process(raw, &mut tracker, &mut engine);
            }
            // Idle timeout — no packet in the last second, loop again.
            Ok(None) => continue,
            Err(e) => {
                eprintln!("capture error: {e:?}");
                break;
            }
        }
    }

    println!("---");
    println!("packets decoded : {packet_count}");
    println!("conversations   : {}", tracker.conversations.len());
    println!("alerts fired    : {alert_count}");
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
        Ok(Mode::File(path)) => run_file(&path),
        Ok(Mode::Live(iface)) => run_live(&iface),
        Ok(Mode::ListInterfaces) => run_list_interfaces(),
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}
