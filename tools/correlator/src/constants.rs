// ══════════════════════════════════════════════════════════════
// Detection Thresholds
// ══════════════════════════════════════════════════════════════
// These are the minimum confidence scores at which a detector
// emits a Finding. Values below this are considered noise.

/// Minimum confidence for most detectors to emit a finding.
pub const FINDING_THRESHOLD: f64 = 0.35;

/// Bot detector uses a higher threshold — periodic behavior
/// alone isn't enough, we want strong signal before flagging.
pub const BOT_THRESHOLD: f64 = 0.40;

/// Minimum packets an IP must have before any detector runs.
/// Fewer than this gives statistically meaningless results.
pub const MIN_PACKETS_FOR_DETECTION: u64 = 8;

// ══════════════════════════════════════════════════════════════
// Browser Detector
// ══════════════════════════════════════════════════════════════

/// HTTPS connections needed to suggest browsing activity.
pub const BROWSER_HTTPS_MIN: u64 = 15;
/// Unique DNS domains resolved — browsers touch many CDNs.
pub const BROWSER_DOMAINS_MIN: usize = 20;
/// Ephemeral source ports — browsers open many connections.
pub const BROWSER_SRC_PORTS_MIN: usize = 25;
/// Known browser CDN domains that must be contacted.
pub const BROWSER_CDN_HITS_MIN: usize = 3;
/// Port entropy above this suggests diverse outbound connections.
pub const BROWSER_PORT_ENTROPY_MIN: f64 = 2.5;
/// Distinct destination IPs — browsers fan out.
pub const BROWSER_DEST_IPS_MIN: usize = 10;

// ══════════════════════════════════════════════════════════════
// Bot / Beacon Detectors
// ══════════════════════════════════════════════════════════════

/// Minimum packets before bot detection runs.
pub const BOT_MIN_PACKETS: u64 = 15;
/// Inter-arrival times below this (seconds) are filtered as noise.
pub const BOT_INTERVAL_NOISE_FLOOR: f64 = 0.01;
/// Minimum interval samples for statistical analysis.
pub const BOT_MIN_SAMPLES: usize = 5;
/// Coefficient of variation below this + mean above this = precision beacon.
pub const BOT_PRECISION_CV: f64 = 0.1;
pub const BOT_PRECISION_MEAN: f64 = 0.5;
/// Looser CV/mean for "regular interval" detection.
pub const BOT_REGULAR_CV: f64 = 0.2;
pub const BOT_REGULAR_MEAN: f64 = 1.0;
/// Autocorrelation above this = strongly periodic.
pub const BOT_AUTOCORR_MIN: f64 = 0.7;
/// Fraction of traffic to single port that suggests monotonic behavior.
pub const BOT_MONOTONIC_PORT_PCT: f64 = 0.85;
pub const BOT_MONOTONIC_PORT_MIN: u64 = 30;
/// Few DNS domains + high outbound = pre-programmed IPs.
pub const BOT_LOW_DNS_DOMAINS: usize = 2;
pub const BOT_LOW_DNS_OUTBOUND: u64 = 40;
/// Burst score in this range = regular burst pattern.
pub const BOT_BURST_MIN: f64 = 0.0;
pub const BOT_BURST_MAX: f64 = 0.3;

// Beacon detector (tight/jittered)
pub const BEACON_INTERVAL_NOISE_FLOOR: f64 = 0.1;
pub const BEACON_MIN_SAMPLES: usize = 10;
pub const BEACON_MIN_MEAN: f64 = 0.5;
/// Tight beacon: very low CV, high mean interval.
pub const BEACON_TIGHT_CV: f64 = 0.05;
pub const BEACON_TIGHT_MEAN: f64 = 5.0;
/// Jittered beacon: moderate CV, long interval.
pub const BEACON_JITTER_CV_MIN: f64 = 0.05;
pub const BEACON_JITTER_CV_MAX: f64 = 0.25;
pub const BEACON_JITTER_MEAN: f64 = 10.0;

// C2 beacon detector
pub const C2_INTERVAL_NOISE_FLOOR: f64 = 0.5;
pub const C2_MIN_SAMPLES: usize = 8;
/// Regular C2: consistent timing.
pub const C2_REGULAR_CV: f64 = 0.15;
pub const C2_REGULAR_MEAN: f64 = 5.0;
/// Jittered C2: moderate variation (evades detection).
pub const C2_JITTER_CV_MIN: f64 = 0.05;
pub const C2_JITTER_CV_MAX: f64 = 0.30;
pub const C2_JITTER_MEAN: f64 = 10.0;
/// Low payload average = keep-alive / check-in.
pub const C2_SMALL_PAYLOAD_MAX: f64 = 8.0;

// ══════════════════════════════════════════════════════════════
// Server Detector
// ══════════════════════════════════════════════════════════════

/// Unique source IPs connecting in — servers have many clients.
pub const SERVER_CLIENTS_MIN: usize = 8;
/// Inbound-to-outbound ratio — servers receive more than they send.
pub const SERVER_INBOUND_RATIO: f64 = 2.0;
/// Dest ports responding to — servers handle diverse client ports.
pub const SERVER_DEST_PORTS_MIN: usize = 15;
/// Session duration (seconds) considered "long-lived".
pub const SERVER_LONG_SESSION_SECS: f64 = 30.0;
pub const SERVER_LONG_SESSIONS_MIN: usize = 3;

// ══════════════════════════════════════════════════════════════
// IoT Detector
// ══════════════════════════════════════════════════════════════

/// IoT devices talk to few external IPs.
pub const IOT_MAX_DEST_IPS: usize = 4;
/// Packets per second below this = low-traffic device.
pub const IOT_MAX_PPS: f64 = 3.0;
/// Few DNS queries = static configuration (typical of IoT).
pub const IOT_MAX_DNS: u64 = 5;
/// Burst score in this range = heartbeat pattern.
pub const IOT_HEARTBEAT_BURST_MIN: f64 = 0.0;
pub const IOT_HEARTBEAT_BURST_MAX: f64 = 0.4;

// ══════════════════════════════════════════════════════════════
// DNS Profiler Detector
// ══════════════════════════════════════════════════════════════

/// Queries per second above this = abnormal DNS activity.
pub const DNS_QPS_HIGH: f64 = 8.0;
/// Unique domains above this = enumeration / DGA.
pub const DNS_DOMAINS_HIGH: usize = 60;
/// Single-label queries (no dots) above this = DGA-like.
pub const DNS_SINGLE_LABELS_HIGH: u64 = 10;

// ══════════════════════════════════════════════════════════════
// Scanner Detector
// ══════════════════════════════════════════════════════════════

/// Unique destination ports above this = port scanning.
pub const SCANNER_PORT_THRESHOLD: usize = 20;
/// Many hosts with few packets each = network sweep.
pub const SCANNER_HOST_THRESHOLD: usize = 15;
pub const SCANNER_PKTS_PER_HOST: f64 = 2.0;
/// High outbound with low response = SYN scan.
pub const SCANNER_OUTBOUND_MIN: u64 = 80;
pub const SCANNER_RESPONSE_RATIO: f64 = 8.0;
/// Fraction of sequential ports that suggests automated scanning.
pub const SCANNER_SEQUENTIAL_RATIO: f64 = 0.5;

// ══════════════════════════════════════════════════════════════
// Streaming Detector
// ══════════════════════════════════════════════════════════════

/// Minimum capture duration (seconds) to detect streaming.
pub const STREAM_MIN_DURATION: f64 = 10.0;
pub const STREAM_SUSTAINED_PKTS: u64 = 200;
pub const STREAM_SUSTAINED_DURATION: f64 = 30.0;
/// UDP must dominate TCP by this factor for streaming signal.
pub const STREAM_UDP_DOMINANCE: u64 = 2;
pub const STREAM_MIN_UDP: u64 = 30;
pub const STREAM_HIGH_PPS: f64 = 30.0;

// ══════════════════════════════════════════════════════════════
// VPN Detector
// ══════════════════════════════════════════════════════════════

/// Few destination IPs + high volume = tunnel.
pub const VPN_MAX_DEST_IPS: usize = 2;
pub const VPN_MIN_PACKETS: u64 = 100;
/// Fraction of traffic to single IP = dedicated tunnel.
pub const VPN_TUNNEL_RATIO: f64 = 0.9;
pub const VPN_TUNNEL_MIN: u64 = 50;
/// Uniform packet sizes suggest encrypted tunnel.
pub const VPN_UNIFORM_VARIANCE_MAX: f64 = 1000.0;

// ══════════════════════════════════════════════════════════════
// Tor Detector
// ══════════════════════════════════════════════════════════════

/// Many source IPs + moderate volume = relay behavior.
pub const TOR_RELAY_CLIENTS_MIN: usize = 10;
pub const TOR_RELAY_PACKETS_MIN: u64 = 50;
/// Long-lived sessions = circuit maintenance.
pub const TOR_CIRCUIT_DURATION: f64 = 60.0;
pub const TOR_CIRCUITS_MIN: usize = 5;

// ══════════════════════════════════════════════════════════════
// Game Detector
// ══════════════════════════════════════════════════════════════

/// Bursty traffic with moderate volume = game client.
pub const GAME_BURST_MIN: f64 = 0.5;
/// PPS in this range = interactive game traffic.
pub const GAME_PPS_MIN: f64 = 10.0;
pub const GAME_PPS_MAX: f64 = 200.0;

// ══════════════════════════════════════════════════════════════
// Lateral Movement Detector
// ══════════════════════════════════════════════════════════════

/// Internal hosts contacted — lateral movement touches many.
pub const LATERAL_MIN_INTERNAL_HOSTS: usize = 4;
/// Management ports used — laterally moving hosts probe services.
pub const LATERAL_MIN_MGMT_PORTS: usize = 3;
/// Fraction of traffic to internal hosts.
pub const LATERAL_INTERNAL_RATIO: f64 = 0.6;
/// Hosts with traffic profiles that overlap.
pub const LATERAL_OVERLAP_MIN: usize = 2;
/// Hosts per second = rapid internal scanning.
pub const LATERAL_SCAN_RATE: f64 = 0.5;

// ══════════════════════════════════════════════════════════════
// Data Exfiltration Detector
// ══════════════════════════════════════════════════════════════

/// Outbound-to-inbound ratio above this = heavy upload.
pub const EXFIL_OUTBOUND_RATIO: f64 = 8.0;
pub const EXFIL_MIN_OUTBOUND: u64 = 50;
/// Fraction of traffic to single external IP.
pub const EXFIL_SINGLE_DEST_PCT: f64 = 0.85;
pub const EXFIL_SINGLE_DEST_MIN: u64 = 40;
/// Few DNS domains + high outbound = pre-configured destination.
pub const EXFIL_LOW_DNS_DOMAINS: usize = 3;
pub const EXFIL_LOW_DNS_OUTBOUND: u64 = 60;
/// Sustained exfiltration over time.
pub const EXFIL_SUSTAINED_DURATION: f64 = 60.0;
pub const EXFIL_SUSTAINED_OUTBOUND: u64 = 100;

// ══════════════════════════════════════════════════════════════
// Network Recon Detector
// ══════════════════════════════════════════════════════════════

/// Management ports probed — recon touches many services.
pub const RECON_MIN_MGMT_PORTS: usize = 3;
/// Internal hosts targeted.
pub const RECON_MIN_INTERNAL_HOSTS: usize = 5;
/// Light touch: few packets per host = probing, not using.
pub const RECON_MAX_PKTS_PER_HOST: f64 = 5.0;

// ══════════════════════════════════════════════════════════════
// Printer/IoT Detector
// ══════════════════════════════════════════════════════════════

/// Very low packet rate = embedded device.
pub const PRINTER_MAX_PPS: f64 = 2.0;

// ══════════════════════════════════════════════════════════════
// Profile Builder
// ══════════════════════════════════════════════════════════════

/// Rough MTU estimate for web traffic (HTTP/HTTPS ports).
pub const MTU_WEB: u64 = 1500;
/// Rough estimate for non-web traffic.
pub const MTU_SMALL: u64 = 64;
/// Ports below this are privileged / well-known.
pub const PRIVILEGED_PORT_MAX: u32 = 1024;
/// Ports above this are ephemeral.
pub const EPHEMERAL_PORT_MIN: u32 = 49152;
/// Minimum temporal bins for burst detection.
pub const MIN_BINS_FOR_BURST: usize = 3;

// ══════════════════════════════════════════════════════════════
// Stealth Levels (higher = more hidden)
// ══════════════════════════════════════════════════════════════

/// Level 0: Full scan — default, aggressive nmap, background scanner active.
pub const STEALTH_FULL: u8 = 0;
/// Level 1: Light — rate-limited nmap, slower background scanner.
pub const STEALTH_LIGHT: u8 = 1;
/// Level 2: Passive — TShark only, no active scanning at all.
pub const STEALTH_PASSIVE: u8 = 2;

/// Nmap timing template for each stealth level.
pub const fn nmap_timing(stealth: u8) -> &'static str {
    match stealth {
        0 => "-T4",
        1 => "-T2",
        _ => "-T1",
    }
}

/// Whether to run the background scanner at this stealth level.
pub const fn background_scanner_enabled(stealth: u8) -> bool {
    stealth < STEALTH_PASSIVE
}

/// Background scanner interval (seconds) per stealth level.
pub const fn background_scanner_interval(stealth: u8) -> u64 {
    match stealth {
        0 => 4,
        1 => 30,
        _ => 0, // disabled
    }
}

/// Nmap flags for each stealth level.
pub const fn nmap_flags(stealth: u8, fast: bool) -> &'static [&'static str] {
    match stealth {
        0 => {
            if fast {
                &["-sS", "--top-ports", "100", "--open", "-oX", "-", "-T4", "--min-rate", "1000"]
            } else {
                &["-sV", "-O", "-sC", "--open", "-oX", "-", "-T4"]
            }
        }
        1 => {
            if fast {
                &["-sn", "-T2", "--max-retries", "1", "--host-timeout", "10s"]
            } else {
                &["-sn", "-T2", "--max-retries", "2", "--host-timeout", "15s"]
            }
        }
        _ => &[], // passive — no scanning
    }
}
