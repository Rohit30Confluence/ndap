use ndap_capture::PcapReader;
use ndap_detect::DetectionEngine;
use ndap_flow::ConversationTracker;
use ndap_protocol::decode_packet;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: ndap <file.pcap>");
        return ExitCode::FAILURE;
    }
    let path = &args[1];

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

        let decoded = decode_packet(&raw.data);
        tracker.record(&decoded, raw.ts_sec, raw.ts_usec);

        for alert in engine.feed(&decoded, raw.ts_sec) {
            alert_count += 1;
            println!(
                "[{:>8}] {:?} {} :: {}",
                alert.ts_sec, alert.severity, alert.rule, alert.message
            );
        }
    }

    println!("---");
    println!("packets decoded : {packet_count}");
    println!("conversations   : {}", tracker.conversations.len());
    println!("alerts fired    : {alert_count}");

    ExitCode::SUCCESS
}
