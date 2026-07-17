use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::{json, Value};

// ══════════════════════════════════════════════════════════════
// Data Structures
// ══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct Packet {
    pub epoch: f64,
    pub ip_src: Option<String>,
    pub ip_dst: Option<String>,
    pub tcp_src_port: Option<u32>,
    pub tcp_dst_port: Option<u32>,
    pub udp_src_port: Option<u32>,
    pub udp_dst_port: Option<u32>,
    pub dns_query: Option<String>,
}

/// TCP connection lifecycle tracking
#[derive(Debug, Clone, Default)]
pub struct TcpSession {
    pub src: String,
    pub dst: String,
    pub src_port: u32,
    pub dst_port: u32,
    pub first_packet: f64,
    pub last_packet: f64,
    pub pkt_count: u64,
    pub bytes_approx: u64,
    pub syn_seen: bool,
    pub synack_seen: bool,
    pub fin_seen: bool,
    pub rst_seen: bool,
}

/// Temporal pattern for timing analysis
#[derive(Debug, Clone)]
pub struct TemporalBin {
    pub start: f64,
    pub end: f64,
    pub count: u64,
}

/// Per-IP behavioral profile — the core of correlation
#[derive(Debug, Clone)]
pub struct IpProfile {
    pub ip: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub packet_count: u64,

    // Connection topology
    pub dest_ips: HashMap<String, u64>,
    pub src_ips: HashMap<String, u64>,
    pub dest_ports: HashMap<u32, u64>,
    pub src_ports: HashMap<u32, u64>,
    pub unique_connections: u64,

    // Sessions (src_port → dst_ip:dst_port)
    pub sessions: HashMap<(String, u32, String, u32), TcpSession>,

    // DNS behavior
    pub dns_queries: Vec<String>,
    pub dns_domains: HashMap<String, u64>,
    pub dns_single_labels: u64,

    // Protocol counts
    pub tcp_count: u64,
    pub udp_count: u64,
    pub dns_count: u64,
    pub icmp_count: u64,

    // Direction
    pub inbound_count: u64,
    pub outbound_count: u64,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,

    // Timing — per-second resolution
    pub temporal_bins: Vec<TemporalBin>,
    pub inter_arrival_times: Vec<f64>,

    // Port entropy — how diverse are the ports used
    pub dest_port_entropy: f64,
    pub src_port_entropy: f64,

    // Protocol fingerprinting — which ports are used
    pub well_known_ports: Vec<u32>,
    pub ephemeral_ports: Vec<u32>,
    pub privileged_ports: Vec<u32>,

    // Anomaly tracking
    pub packet_size_variance: f64,
    pub avg_packet_size: f64,
    pub burst_score: f64,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub ip: String,
    pub kind: FindingKind,
    pub confidence: f64,
    pub detail: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FindingKind {
    Browser,
    Bot,
    Server,
    IoTDevice,
    DNSProfiler,
    Beacon,
    Scanner,
    StreamingMedia,
    CloudSync,
    VPN,
    Tor,
    GameClient,
    IoTCoordinator,
    LateralMovement,
    DataExfil,
    C2Beacon,
    NetworkRecon,
    PrinterIoT,
    Unknown,
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingKind::Browser => write!(f, "BROWSER"),
            FindingKind::Bot => write!(f, "BOT"),
            FindingKind::Server => write!(f, "SERVER"),
            FindingKind::IoTDevice => write!(f, "IOT"),
            FindingKind::DNSProfiler => write!(f, "DNS_PROFILER"),
            FindingKind::Beacon => write!(f, "BEACON"),
            FindingKind::Scanner => write!(f, "SCANNER"),
            FindingKind::StreamingMedia => write!(f, "STREAMING"),
            FindingKind::CloudSync => write!(f, "CLOUD_SYNC"),
            FindingKind::VPN => write!(f, "VPN"),
            FindingKind::Tor => write!(f, "TOR"),
            FindingKind::GameClient => write!(f, "GAME"),
            FindingKind::IoTCoordinator => write!(f, "IOT_COORD"),
            FindingKind::LateralMovement => write!(f, "LATERAL_MOVEMENT"),
            FindingKind::DataExfil => write!(f, "DATA_EXFIL"),
            FindingKind::C2Beacon => write!(f, "C2_BEACON"),
            FindingKind::NetworkRecon => write!(f, "NET_RECON"),
            FindingKind::PrinterIoT => write!(f, "PRINTER_IOT"),
            FindingKind::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({}%) — {}", self.kind, self.ip, (self.confidence * 100.0) as u32, self.detail)
    }
}

// ══════════════════════════════════════════════════════════════
// Profile Builder
// ══════════════════════════════════════════════════════════════

fn shannon_entropy(values: &[u32]) -> f64 {
    if values.is_empty() { return 0.0; }
    let total = values.len() as f64;
    let mut freq: HashMap<u32, u64> = HashMap::new();
    for &v in values { *freq.entry(v).or_insert(0) += 1; }
    freq.values()
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn shannon_entropy_u64(values: &[u64]) -> f64 {
    if values.is_empty() { return 0.0; }
    let total = values.len() as f64;
    let mut freq: HashMap<u64, u64> = HashMap::new();
    for &v in values { *freq.entry(v).or_insert(0) += 1; }
    freq.values()
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

impl IpProfile {
    fn new(ip: &str) -> Self {
        Self {
            ip: ip.to_string(),
            first_seen: f64::MAX,
            last_seen: f64::MIN,
            packet_count: 0,
            dest_ips: HashMap::new(),
            src_ips: HashMap::new(),
            dest_ports: HashMap::new(),
            src_ports: HashMap::new(),
            unique_connections: 0,
            sessions: HashMap::new(),
            dns_queries: Vec::new(),
            dns_domains: HashMap::new(),
            dns_single_labels: 0,
            tcp_count: 0,
            udp_count: 0,
            dns_count: 0,
            icmp_count: 0,
            inbound_count: 0,
            outbound_count: 0,
            inbound_bytes: 0,
            outbound_bytes: 0,
            temporal_bins: Vec::new(),
            inter_arrival_times: Vec::new(),
            dest_port_entropy: 0.0,
            src_port_entropy: 0.0,
            well_known_ports: Vec::new(),
            ephemeral_ports: Vec::new(),
            privileged_ports: Vec::new(),
            packet_size_variance: 0.0,
            avg_packet_size: 0.0,
            burst_score: 0.0,
        }
    }

    fn ingest(&mut self, pkt: &Packet) {
        self.packet_count += 1;
        self.first_seen = self.first_seen.min(pkt.epoch);
        self.last_seen = self.last_seen.max(pkt.epoch);

        let is_src = pkt.ip_src.as_deref() == Some(&self.ip);
        let is_dst = pkt.ip_dst.as_deref() == Some(&self.ip);

        if is_src {
            self.outbound_count += 1;
            if let Some(ref dst) = pkt.ip_dst {
                let entry = self.dest_ips.entry(dst.clone()).or_insert(0);
                *entry += 1;
            }
            let all_ports: Vec<u32> = [pkt.tcp_dst_port, pkt.udp_dst_port].into_iter().flatten().collect();
            for port in &all_ports {
                *self.dest_ports.entry(*port).or_insert(0) += 1;
            }
        }

        if is_dst {
            self.inbound_count += 1;
            if let Some(ref src) = pkt.ip_src {
                *self.src_ips.entry(src.clone()).or_insert(0) += 1;
            }
            let all_ports: Vec<u32> = [pkt.tcp_src_port, pkt.udp_src_port].into_iter().flatten().collect();
            for port in &all_ports {
                *self.src_ports.entry(*port).or_insert(0) += 1;
            }
        }

        // Session tracking
        if let (Some(ref src), Some(ref dst)) = (&pkt.ip_src, &pkt.ip_dst) {
            if let (Some(sp), Some(dp)) = (pkt.tcp_src_port, pkt.tcp_dst_port) {
                let key = (src.clone(), sp, dst.clone(), dp);
                let session = self.sessions.entry(key.clone()).or_insert_with(|| {
                    TcpSession { src: src.clone(), dst: dst.clone(), src_port: sp, dst_port: dp, first_packet: pkt.epoch, ..Default::default() }
                });
                session.last_packet = pkt.epoch;
                session.pkt_count += 1;
                if sp == 80 || sp == 443 || dp == 80 || dp == 443 {
                    session.bytes_approx += 1500; // rough MTU estimate
                } else {
                    session.bytes_approx += 64;
                }
            }
        }

        // Protocol
        if pkt.tcp_src_port.is_some() || pkt.tcp_dst_port.is_some() {
            self.tcp_count += 1;
        }
        if pkt.udp_src_port.is_some() || pkt.udp_dst_port.is_some() {
            self.udp_count += 1;
        }

        // DNS
        if let Some(ref q) = pkt.dns_query {
            self.dns_count += 1;
            self.dns_queries.push(q.clone());
            let domain = extract_domain(q);
            *self.dns_domains.entry(domain).or_insert(0) += 1;
            if q.split('.').count() == 1 {
                self.dns_single_labels += 1;
            }
        }

        // Inter-arrival time
        if !self.inter_arrival_times.is_empty() {
            let last = self.inter_arrival_times.last().copied().unwrap_or(0.0);
            if last > 0.0 {
                self.inter_arrival_times.push(pkt.epoch - last);
            }
        }
        self.inter_arrival_times.push(pkt.epoch);

        // Temporal bins (1-second resolution)
        let bin_start = pkt.epoch.floor();
        if let Some(last_bin) = self.temporal_bins.last_mut() {
            if (last_bin.start - bin_start).abs() < f64::EPSILON {
                last_bin.count += 1;
                last_bin.end = last_bin.end.max(pkt.epoch);
            } else {
                self.temporal_bins.push(TemporalBin { start: bin_start, end: pkt.epoch, count: 1 });
            }
        } else {
            self.temporal_bins.push(TemporalBin { start: bin_start, end: pkt.epoch, count: 1 });
        }
    }

    fn finalize(&mut self) {
        // Port entropy
        let all_dst_ports: Vec<u32> = self.dest_ports.keys().copied().collect();
        self.dest_port_entropy = shannon_entropy(&all_dst_ports);
        let all_src_ports: Vec<u32> = self.src_ports.keys().copied().collect();
        self.src_port_entropy = shannon_entropy(&all_src_ports);

        // Port classification
        for &port in self.src_ports.keys() {
            if port < 1024 { self.privileged_ports.push(port); }
            else if port >= 49152 { self.ephemeral_ports.push(port); }
            else { self.well_known_ports.push(port); }
        }

        // Unique connections
        self.unique_connections = self.sessions.len() as u64 +
            self.dest_ips.len() as u64 +
            self.src_ips.len() as u64;

        // Burst detection
        if self.temporal_bins.len() >= 3 {
            let counts: Vec<u64> = self.temporal_bins.iter().map(|b| b.count).collect();
            let mean = counts.iter().sum::<u64>() as f64 / counts.len() as f64;
            if mean > 0.0 {
                let variance = counts.iter().map(|&c| (c as f64 - mean).powi(2)).sum::<f64>() / counts.len() as f64;
                self.burst_score = variance.sqrt() / mean; // CV
            }
        }
    }
}

fn extract_domain(fqdn: &str) -> String {
    let labels: Vec<&str> = fqdn.split('.').collect();
    if labels.len() >= 2 { labels[labels.len() - 2..].join(".") } else { fqdn.to_string() }
}

// ══════════════════════════════════════════════════════════════
// Advanced Detectors
// ══════════════════════════════════════════════════════════════

const BROWSER_DOMAINS: &[&str] = &[
    "google.com", "googleapis.com", "gstatic.com", "cloudflare.com",
    "mozilla.org", "apple.com", "microsoft.com", "windows.com", "windowsupdate.com",
    "akamai.net", "akamaized.net", "fastly.net", "facebook.com", "fbcdn.net",
    "twitter.com", "x.com", "youtube.com", "ytimg.com", "amazonaws.com",
    "azureedge.net", "edgecastcdn.net", "cloudfront.net", "bing.com",
    "reddit.com", "redditstatic.com", "discord.com", "discordapp.com",
];

const CDN_DOMAINS: &[&str] = &[
    "akamai.net", "akamaized.net", "cloudfront.net", "fastly.net",
    "cloudflare.com", "azureedge.net", "edgecastcdn.net", "cdn",
];

const CLOUD_DOMAINS: &[&str] = &[
    "icloud.com", "apple.com", "googleapis.com", "drive.google.com",
    "dropbox.com", "onedrive.live.com", "box.com", "sync", "backup",
    "amazonaws.com", "azure.com", "backblaze.com",
];

const STREAMING_DOMAINS: &[&str] = &[
    "video", "media", "hls", "dash", "stream", "netflix.com",
    "hulu.com", "primevideo.com", "disneyplus.com", "hbomax.com",
    "twitch.tv", "ttvnw.net", "youtube.com", "youtu.be", "vimeo.com",
    "soundcloud.com", "spotify.com",
];

const IOT_PORTS: &[u32] = &[
    5353, 1900, 5355, 5683, 5684, 8883, 1883, 5672, 15672, 8083,
];

const GAME_PORTS: &[u32] = &[
    27015, 27016, 27017, 27018, 27019, 27020, // Steam
    3478, 3479, 3480, // PlayStation
    3074, // Xbox
    6112, 6113, 6114, 6115, // Battle.net
    1119, 1120, 3724, 6113, // Blizzard
    25565, 25566, 19132, 19133, // Minecraft
    7777, 27015, // Unreal Engine
];

const TOR_PORTS: &[u32] = &[9001, 9002, 9003, 9030, 9031, 9150, 443];

fn detect_browser(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let https_dests = profile.dest_ports.get(&443).copied().unwrap_or(0);
    if https_dests > 15 {
        score += 0.25;
        indicators.push(format!("{} HTTPS connections", https_dests));
    }

    if profile.dns_domains.len() > 20 {
        score += 0.25;
        indicators.push(format!("{} unique domains resolved", profile.dns_domains.len()));
    }

    if profile.src_ports.len() > 25 {
        score += 0.15;
        indicators.push(format!("{} ephemeral source ports", profile.src_ports.len()));
    }

    // Browser domains
    let browser_hits: Vec<_> = profile.dns_domains.keys()
        .filter(|d| BROWSER_DOMAINS.iter().any(|bd| d.ends_with(bd)))
        .collect();
    if browser_hits.len() >= 3 {
        score += 0.2;
        indicators.push(format!("{} browser CDNs contacted", browser_hits.len()));
    }

    // Port entropy — browsers have high entropy (many different ports)
    if profile.dest_port_entropy > 2.5 {
        score += 0.1;
        indicators.push(format!("high port entropy: {:.2}", profile.dest_port_entropy));
    }

    // Connection diversity
    if profile.dest_ips.len() > 10 {
        score += 0.1;
        indicators.push(format!("{} distinct destination IPs", profile.dest_ips.len()));
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::Browser,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_bot(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    if profile.packet_count < 15 { return None; }

    // Regular interval detection via autocorrelation
    let intervals: Vec<f64> = profile.inter_arrival_times.windows(2)
        .map(|w| (w[1] - w[0]).abs())
        .filter(|&x| x > 0.01)
        .collect();

    if intervals.len() >= 5 {
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean > 0.0 {
            let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
            let cv = variance.sqrt() / mean;

            if cv < 0.1 && mean > 0.5 {
                score += 0.4;
                indicators.push(format!("precision beacon: {:.2}s interval (CV: {:.4})", mean, cv));
            } else if cv < 0.2 && mean > 1.0 {
                score += 0.3;
                indicators.push(format!("regular interval: {:.1}s (CV: {:.3})", mean, cv));
            }

            // Detect exactly periodic patterns
            let mut autocorr: f64 = 0.0;
            let n = intervals.len();
            for lag in 1..n.min(20) {
                let mut sum = 0.0;
                let mut count = 0;
                for i in 0..n - lag {
                    sum += (intervals[i] - mean) * (intervals[i + lag] - mean);
                    count += 1;
                }
                if count > 0 {
                    let corr = sum / (count as f64 * variance.max(0.001));
                    autocorr = autocorr.max(corr);
                }
            }
            if autocorr > 0.7 {
                score += 0.2;
                indicators.push(format!("high autocorrelation: {:.3}", autocorr));
            }
        }
    }

    // Monotonic port behavior
    if let Some((&port, &count)) = profile.dest_ports.iter().max_by_key(|(_, c)| *c) {
        let pct = count as f64 / profile.packet_count as f64;
        if pct > 0.85 && count > 30 {
            score += 0.25;
            indicators.push(format!("{:.0}% of traffic to port {}", pct * 100.0, port));
        }
    }

    // Low DNS diversity despite high connections
    if profile.dns_domains.len() <= 2 && profile.outbound_count > 40 {
        score += 0.2;
        indicators.push("pre-programmed IPs, minimal DNS".into());
    }

    // Burst pattern — very consistent bursts
    if profile.burst_score > 0.0 && profile.burst_score < 0.3 && profile.packet_count > 50 {
        score += 0.1;
        indicators.push(format!("regular burst pattern (CV: {:.3})", profile.burst_score));
    }

    if score >= 0.4 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::Bot,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_server(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    // Many unique source IPs connecting in
    if profile.src_ips.len() > 8 {
        score += 0.3;
        indicators.push(format!("{} unique clients", profile.src_ips.len()));
    }

    // Listening on well-known ports
    let listening: Vec<_> = profile.src_ports.keys()
        .filter(|p| **p < 1024)
        .collect();
    if !listening.is_empty() {
        score += 0.25;
        indicators.push(format!("listening on: {}", listening.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
    }

    // Inbound-heavy ratio
    if profile.inbound_count > 0 {
        let ratio = profile.inbound_count as f64 / profile.outbound_count.max(1) as f64;
        if ratio > 2.0 {
            score += 0.2;
            indicators.push(format!("inbound ratio: {:.1}:1", ratio));
        }
    }

    // Responding to many client ports
    if profile.dest_ports.len() > 15 {
        score += 0.15;
        indicators.push(format!("responding to {} client ports", profile.dest_ports.len()));
    }

    // Long-lived sessions
    let long_sessions = profile.sessions.values().filter(|s| s.last_packet - s.first_packet > 30.0).count();
    if long_sessions > 3 {
        score += 0.1;
        indicators.push(format!("{} long-lived sessions", long_sessions));
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::Server,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_iot(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    // Multicast/mDNS/SSDP
    let multicast_hits: Vec<_> = profile.dest_ports.keys().filter(|p| IOT_PORTS.contains(p)).collect();
    if !multicast_hits.is_empty() {
        score += 0.3;
        indicators.push(format!("multicast: {}", multicast_hits.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
    }

    // Few external connections
    if profile.dest_ips.len() <= 4 && profile.packet_count > 30 {
        score += 0.15;
        indicators.push(format!("only {} external IPs", profile.dest_ips.len()));
    }

    // Low packet rate
    let duration = profile.last_seen - profile.first_seen;
    if duration > 0.0 {
        let pps = profile.packet_count as f64 / duration;
        if pps < 3.0 && profile.packet_count > 20 {
            score += 0.15;
            indicators.push(format!("low rate: {:.1} pps", pps));
        }
    }

    // Few DNS queries
    if profile.dns_count < 5 && profile.packet_count > 30 {
        score += 0.15;
        indicators.push(format!("{} DNS queries", profile.dns_count));
    }

    // Regular heartbeat
    if profile.burst_score < 0.4 && profile.burst_score > 0.0 && duration > 10.0 {
        score += 0.1;
        indicators.push("heartbeat pattern".into());
    }

    // UDP-dominant (many IoT protocols use UDP)
    if profile.udp_count > profile.tcp_count && profile.udp_count > 15 {
        score += 0.1;
        indicators.push("UDP-dominant".into());
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::IoTDevice,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_dns_profiler(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let duration = profile.last_seen - profile.first_seen;
    if duration > 0.0 {
        let qps = profile.dns_count as f64 / duration;
        if qps > 8.0 {
            score += 0.35;
            indicators.push(format!("high DNS rate: {:.1} qps", qps));
        }
    }

    if profile.dns_domains.len() > 60 {
        score += 0.3;
        indicators.push(format!("{} unique domains", profile.dns_domains.len()));
    }

    if profile.dns_count > 25 && profile.outbound_count < profile.dns_count / 4 {
        score += 0.2;
        indicators.push("probing domains without connecting".into());
    }

    // Single-label DNS queries (DGA-like behavior)
    if profile.dns_single_labels > 10 {
        score += 0.15;
        indicators.push(format!("{} single-label queries", profile.dns_single_labels));
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::DNSProfiler,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_beacon(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let intervals: Vec<f64> = profile.inter_arrival_times.windows(2)
        .map(|w| (w[1] - w[0]).abs())
        .filter(|&x| x > 0.1)
        .collect();

    if intervals.len() < 10 { return None; }

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < 0.5 { return None; }

    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let cv = variance.sqrt() / mean;

    // Tight beacon
    if cv < 0.05 && mean > 5.0 {
        score += 0.5;
        indicators.push(format!("tight beacon: {:.1}s ± {:.3}s (CV: {:.4})", mean, variance.sqrt(), cv));
    }

    // Jittered beacon (common in C2)
    if cv > 0.05 && cv < 0.25 && mean > 10.0 {
        score += 0.35;
        indicators.push(format!("jittered beacon: {:.1}s (CV: {:.3})", mean, cv));
    }

    // Consistent to single destination
    if profile.dest_ips.len() == 1 && profile.dns_count < 3 {
        score += 0.2;
        indicators.push("single C2 destination".into());
    }

    // Low payload, regular timing = keep-alive
    if profile.packet_count > 30 && profile.avg_packet_size < 200.0 {
        score += 0.1;
        indicators.push("low-payload keep-alive".into());
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::Beacon,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_scanner(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    if profile.dest_ports.len() > 20 {
        score += 0.35;
        indicators.push(format!("port scanning: {} unique ports", profile.dest_ports.len()));
    }

    let avg_pkts_per_dest = if profile.dest_ips.len() > 0 {
        profile.outbound_count as f64 / profile.dest_ips.len() as f64
    } else {
        0.0
    };

    if profile.dest_ips.len() > 15 && avg_pkts_per_dest < 2.0 {
        score += 0.3;
        indicators.push(format!("network scan: {} hosts, {:.1} pkts/host", profile.dest_ips.len(), avg_pkts_per_dest));
    }

    if profile.outbound_count > 80 && profile.inbound_count < profile.outbound_count / 8 {
        score += 0.2;
        indicators.push("SYN scan pattern (high outbound, low response)".into());
    }

    // Sequential port scanning
    let mut ports: Vec<u32> = profile.dest_ports.keys().copied().collect();
    ports.sort();
    if ports.len() >= 5 {
        let mut sequential = 0;
        for w in ports.windows(2) {
            if w[1] - w[0] <= 2 { sequential += 1; }
        }
        if sequential as f64 / ports.len() as f64 > 0.5 {
            score += 0.15;
            indicators.push("sequential port scan".into());
        }
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::Scanner,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_streaming(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let duration = profile.last_seen - profile.first_seen;
    if duration < 10.0 { return None; }

    // Sustained high volume
    if profile.packet_count > 200 && duration > 30.0 {
        score += 0.2;
        indicators.push(format!("sustained: {:.0}s, {} pkts", duration, profile.packet_count));
    }

    // CDN domains
    let cdn_hits: Vec<_> = profile.dns_domains.keys()
        .filter(|d| STREAMING_DOMAINS.iter().any(|sd| d.contains(sd)))
        .collect();
    if !cdn_hits.is_empty() {
        score += 0.3;
        indicators.push(format!("streaming services: {}", cdn_hits.iter().take(3).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }

    // UDP-dominant (video streaming often uses UDP/DASH)
    if profile.udp_count > profile.tcp_count * 2 && profile.udp_count > 30 {
        score += 0.2;
        indicators.push(format!("UDP-dominant: {} UDP, {} TCP", profile.udp_count, profile.tcp_count));
    }

    // High packet rate
    if duration > 0.0 {
        let pps = profile.packet_count as f64 / duration;
        if pps > 30.0 {
            score += 0.15;
            indicators.push(format!("high rate: {:.0} pps", pps));
        }
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::StreamingMedia,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_cloud_sync(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let cloud_hits: Vec<_> = profile.dns_domains.keys()
        .filter(|d| CLOUD_DOMAINS.iter().any(|cd| d.contains(cd)))
        .collect();
    if !cloud_hits.is_empty() {
        score += 0.3;
        indicators.push(format!("cloud: {}", cloud_hits.iter().take(3).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }

    if profile.dns_domains.len() <= 5 && profile.dns_count > 15 {
        let top = profile.dns_domains.iter().max_by_key(|(_, c)| *c);
        if let Some((domain, count)) = top {
            if *count > 8 {
                score += 0.2;
                indicators.push(format!("repeated {}: {}x", domain, count));
            }
        }
    }

    // Steady bidirectional
    if profile.inbound_count > 15 && profile.outbound_count > 15 {
        let ratio = (profile.inbound_count as f64 / profile.outbound_count as f64)
            .min(profile.outbound_count as f64 / profile.inbound_count as f64);
        if ratio > 0.3 {
            score += 0.15;
            indicators.push("steady bidirectional sync".into());
        }
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::CloudSync,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_vpn(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    // VPN typically connects to single IP on specific ports
    let vpn_ports = [1194, 4500, 500, 1723, 1195, 8443, 443];
    let vpn_port_hits: Vec<_> = profile.dest_ports.iter()
        .filter(|(p, _)| vpn_ports.contains(p))
        .collect();
    if !vpn_port_hits.is_empty() {
        score += 0.3;
        indicators.push(format!("VPN ports: {}", vpn_port_hits.iter().map(|(p, c)| format!("{}({})", p, c)).collect::<Vec<_>>().join(", ")));
    }

    // Single destination with high volume
    if profile.dest_ips.len() <= 2 && profile.packet_count > 100 {
        score += 0.2;
        indicators.push(format!("tunnel to {} IPs", profile.dest_ips.len()));
    }

    // High packet rate to single destination
    if let Some((ip, &count)) = profile.dest_ips.iter().max_by_key(|(_, c)| *c) {
        if count as f64 / profile.packet_count as f64 > 0.9 && count > 50 {
            score += 0.2;
            indicators.push(format!("dedicated tunnel to {}", ip));
        }
    }

    // Encrypted bulk transfer pattern — consistent packet sizes
    if profile.packet_count > 50 && profile.packet_size_variance < 1000.0 {
        score += 0.1;
        indicators.push("uniform packet sizes (encrypted tunnel)".into());
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::VPN,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_tor(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    // Tor relay ports
    let tor_port_hits: Vec<_> = profile.src_ports.keys()
        .filter(|p| TOR_PORTS.contains(p))
        .collect();
    if !tor_port_hits.is_empty() {
        score += 0.35;
        indicators.push(format!("Tor ports: {}", tor_port_hits.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
    }

    // Tor relay behavior: many connections, moderate volume
    if profile.src_ips.len() > 10 && profile.packet_count > 50 {
        score += 0.2;
        indicators.push(format!("relay behavior: {} clients, {} pkts", profile.src_ips.len(), profile.packet_count));
    }

    // Long-lived connections
    let long = profile.sessions.values().filter(|s| s.last_packet - s.first_packet > 60.0).count();
    if long > 5 {
        score += 0.15;
        indicators.push(format!("{} long-lived circuits", long));
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::Tor,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_game(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let game_port_hits: Vec<_> = profile.dest_ports.keys()
        .filter(|p| GAME_PORTS.contains(p))
        .collect();
    if !game_port_hits.is_empty() {
        score += 0.35;
        indicators.push(format!("game ports: {}", game_port_hits.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
    }

    // Games: bursty traffic, moderate packet rate
    if profile.burst_score > 0.5 && profile.packet_count > 50 {
        score += 0.2;
        indicators.push(format!("bursty pattern (CV: {:.2})", profile.burst_score));
    }

    // Low latency: small packets, frequent
    let duration = profile.last_seen - profile.first_seen;
    if duration > 0.0 {
        let pps = profile.packet_count as f64 / duration;
        if pps > 10.0 && pps < 200.0 {
            score += 0.15;
            indicators.push(format!("game-like rate: {:.0} pps", pps));
        }
    }

    // UDP-heavy (many games use UDP)
    if profile.udp_count > profile.tcp_count {
        score += 0.1;
        indicators.push("UDP-dominant".into());
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::GameClient,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 { return false; }
    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse().ok()).collect();
    if octets.len() != 4 { return false; }
    match octets[0] {
        10 => true,
        172 => octets[1] >= 16 && octets[1] <= 31,
        192 => octets[1] == 168,
        _ => false,
    }
}

fn detect_lateral_movement(profile: &IpProfile, all_profiles: &HashMap<String, IpProfile>) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let internal_dests: Vec<_> = profile.dest_ips.keys().filter(|ip| is_private_ip(ip)).collect();
    let internal_count = internal_dests.len();

    if internal_count < 4 { return None; }

    score += 0.25;
    indicators.push(format!("connecting to {} internal hosts", internal_count));

    let unique_ports: Vec<_> = profile.dest_ports.keys().filter(|p| **p < 1024 || **p == 8080 || **p == 3389).collect();
    if unique_ports.len() >= 3 {
        score += 0.25;
        indicators.push(format!("using {} management ports: {}", unique_ports.len(),
            unique_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
    }

    let internal_pkts: u64 = profile.dest_ips.iter()
        .filter(|(ip, _)| is_private_ip(ip))
        .map(|(_, c)| c)
        .sum();
    let total_out = profile.outbound_count.max(1) as f64;
    let internal_ratio = internal_pkts as f64 / total_out;
    if internal_ratio > 0.6 {
        score += 0.2;
        indicators.push(format!("{:.0}% traffic to internal hosts", internal_ratio * 100.0));
    }

    let others_can_see: Vec<_> = internal_dests.iter()
        .filter(|dest| all_profiles.contains_key(dest.as_str()))
        .collect();
    if others_can_see.len() >= 2 {
        score += 0.15;
        indicators.push(format!("{} target hosts have traffic profiles", others_can_see.len()));
    }

    let duration = profile.last_seen - profile.first_seen;
    if duration > 0.0 && internal_count as f64 / duration > 0.5 {
        score += 0.1;
        indicators.push(format!("rapid internal scanning: {:.1} hosts/s", internal_count as f64 / duration));
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::LateralMovement,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_data_exfil(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let external_dests: Vec<_> = profile.dest_ips.iter()
        .filter(|(ip, _)| !is_private_ip(ip))
        .collect();

    if external_dests.is_empty() { return None; }

    if profile.inbound_count > 0 {
        let ratio = profile.outbound_count as f64 / profile.inbound_count as f64;
        if ratio > 8.0 && profile.outbound_count > 50 {
            score += 0.35;
            indicators.push(format!("high outbound ratio: {:.1}:1 ({} out, {} in)", ratio, profile.outbound_count, profile.inbound_count));
        }
    }

    if let Some((ip, &count)) = external_dests.iter().max_by_key(|(_, c)| *c) {
        let pct = count as f64 / profile.packet_count as f64;
        if pct > 0.85 && count > 40 {
            score += 0.3;
            indicators.push(format!("{}% of outbound to single IP {} ({})", (pct * 100.0) as u32, ip, count));
        }
    }

    if profile.dns_domains.len() <= 3 && profile.outbound_count > 60 {
        score += 0.15;
        indicators.push(format!("only {} DNS domains with {} outbound packets (pre-configured destination)", profile.dns_domains.len(), profile.outbound_count));
    }

    let duration = profile.last_seen - profile.first_seen;
    if duration > 60.0 && profile.outbound_count > 100 {
        score += 0.1;
        indicators.push(format!("sustained over {:.0}s", duration));
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::DataExfil,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_c2_beacon(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let intervals: Vec<f64> = profile.inter_arrival_times.windows(2)
        .map(|w| (w[1] - w[0]).abs())
        .filter(|&x| x > 0.5)
        .collect();

    if intervals.len() < 8 { return None; }

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let cv = variance.sqrt() / mean;

    let is_regular = cv < 0.15 && mean > 5.0;
    let is_jittered = cv >= 0.05 && cv < 0.3 && mean > 10.0;

    if !is_regular && !is_jittered { return None; }

    if is_regular {
        score += 0.3;
        indicators.push(format!("regular beacon: {:.1}s ± {:.3}s (CV: {:.4})", mean, variance.sqrt(), cv));
    } else {
        score += 0.2;
        indicators.push(format!("jittered beacon: {:.1}s (CV: {:.3})", mean, cv));
    }

    let external_dests: Vec<_> = profile.dest_ips.iter().filter(|(ip, _)| !is_private_ip(ip)).collect();
    if external_dests.len() == 1 {
        score += 0.2;
        indicators.push(format!("single external destination: {}", external_dests[0].0));
    }

    if profile.dns_count < 5 && profile.outbound_count > 20 {
        score += 0.15;
        indicators.push(format!("{} DNS queries, {} outbound (minimal DNS)", profile.dns_count, profile.outbound_count));
    }

    let avg_out = if profile.dest_ips.len() > 0 { profile.outbound_count as f64 / profile.dest_ips.len() as f64 } else { 0.0 };
    if avg_out < 8.0 && avg_out > 0.0 {
        score += 0.1;
        indicators.push(format!("small payloads: {:.1} pkts/dest", avg_out));
    }

    if profile.packet_count < 500 && profile.dns_domains.len() <= 2 {
        score += 0.1;
        indicators.push("reconnaissance-style low volume".into());
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::C2Beacon,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_network_recon(profile: &IpProfile) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let mgmt_ports = [22, 23, 80, 443, 8080, 3389, 5900, 21, 2323, 9100];
    let mgmt_port_hits: Vec<_> = profile.dest_ports.keys().filter(|p| mgmt_ports.contains(p)).collect();

    if mgmt_port_hits.len() < 3 { return None; }

    score += 0.3;
    indicators.push(format!("probing management ports: {}", mgmt_port_hits.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));

    let internal_dests: Vec<_> = profile.dest_ips.keys().filter(|ip| is_private_ip(ip)).collect();
    if internal_dests.len() >= 5 {
        score += 0.25;
        indicators.push(format!("targeting {} internal hosts", internal_dests.len()));
    }

    let avg_pkts_per_dest = if internal_dests.len() > 0 {
        profile.outbound_count as f64 / internal_dests.len() as f64
    } else { 0.0 };

    if avg_pkts_per_dest < 5.0 && avg_pkts_per_dest > 0.0 {
        score += 0.2;
        indicators.push(format!("light touch: {:.1} pkts/host (probe pattern)", avg_pkts_per_dest));
    }

    if profile.inbound_count < profile.outbound_count / 4 && profile.outbound_count > 20 {
        score += 0.15;
        indicators.push("mostly unanswered probes".into());
    }

    if profile.dns_count == 0 && internal_dests.len() > 3 {
        score += 0.1;
        indicators.push("no DNS (targeting known IPs)".into());
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::NetworkRecon,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

fn detect_printers_iot(profile: &IpProfile, devices: &[(String, Option<String>, Option<String>, Option<String>, Option<String>, String)]) -> Option<Finding> {
    let mut score: f64 = 0.0;
    let mut indicators = Vec::new();

    let iot_signal_ports = [5353, 1900, 5355, 5683, 5684, 9100, 631];
    let iot_hits: Vec<_> = profile.src_ports.keys().chain(profile.dest_ports.keys())
        .filter(|p| iot_signal_ports.contains(p))
        .collect();
    if !iot_hits.is_empty() {
        score += 0.2;
        indicators.push(format!("IoT ports: {}", iot_hits.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
    }

    let duration = profile.last_seen - profile.first_seen;
    if duration > 0.0 {
        let pps = profile.packet_count as f64 / duration;
        if pps < 2.0 && profile.packet_count > 10 {
            score += 0.2;
            indicators.push(format!("very low rate: {:.2} pps", pps));
        }
    }

    if let Some((_, _, hostname, vendor, os, _)) = devices.iter().find(|(ip, _, _, _, _, _)| ip == &profile.ip) {
        let vendor_lower = vendor.as_deref().unwrap_or("").to_lowercase();
        let os_lower = os.as_deref().unwrap_or("").to_lowercase();
        let host_lower = hostname.as_deref().unwrap_or("").to_lowercase();

        let printer_keywords = ["printer", "print", "brother", "canon", "epson", "hp", "xerox", "ricoh"];
        let iot_keywords = ["smart tv", "roku", "chromecast", "alexa", "echo", "home", "hub", "nest", "ring"];

        if printer_keywords.iter().any(|kw| vendor_lower.contains(kw) || host_lower.contains(kw) || os_lower.contains(kw)) {
            score += 0.3;
            indicators.push(format!("printer detected: vendor={}", vendor.as_deref().unwrap_or("?")));
        }

        if iot_keywords.iter().any(|kw| vendor_lower.contains(kw) || host_lower.contains(kw) || os_lower.contains(kw)) {
            score += 0.25;
            indicators.push(format!("IoT device: host={}", hostname.as_deref().unwrap_or("?")));
        }
    }

    if profile.dns_count < 3 && profile.packet_count > 15 && profile.udp_count > profile.tcp_count {
        score += 0.15;
        indicators.push("low DNS, UDP-dominant (typical of printers/IoT)".into());
    }

    if score >= 0.35 {
        Some(Finding {
            ip: profile.ip.clone(),
            kind: FindingKind::PrinterIoT,
            confidence: score.min(1.0),
            detail: indicators.join("; "),
            indicators,
        })
    } else {
        None
    }
}

// ══════════════════════════════════════════════════════════════
// Correlation Engine
// ══════════════════════════════════════════════════════════════

pub struct Correlator {
    profiles: HashMap<String, IpProfile>,
    packets: Vec<Packet>,
}

impl Correlator {
    pub fn new() -> Self {
        Self { profiles: HashMap::new(), packets: Vec::new() }
    }

    pub fn ingest_packet(&mut self, pkt: Packet) {
        let src = pkt.ip_src.clone();
        let dst = pkt.ip_dst.clone();

        if let Some(ref s) = src {
            self.profiles.entry(s.clone()).or_insert_with(|| IpProfile::new(s)).ingest(&pkt);
        }
        if let Some(ref d) = dst {
            if src.as_ref() != Some(d) {
                self.profiles.entry(d.clone()).or_insert_with(|| IpProfile::new(d)).ingest(&pkt);
            }
        }
        self.packets.push(pkt);
    }

    pub fn ingest_batch(&mut self, packets: Vec<Packet>) {
        for pkt in packets { self.ingest_packet(pkt); }
    }

    pub fn finalize(&mut self) {
        for profile in self.profiles.values_mut() {
            profile.finalize();
        }
    }

    pub fn correlate(&mut self) -> Vec<Finding> {
        self.correlate_with_devices(&[])
    }

    pub fn correlate_with_devices(&mut self, devices: &[(String, Option<String>, Option<String>, Option<String>, Option<String>, String)]) -> Vec<Finding> {
        self.finalize();
        let mut findings = Vec::new();
        let all_profiles = self.profiles.clone();

        for (_ip, profile) in &self.profiles {
            if profile.packet_count < 8 { continue; }

            let mut ip_findings = Vec::new();
            let detectors: Vec<Box<dyn Fn(&IpProfile) -> Option<Finding>>> = vec![
                Box::new(detect_browser),
                Box::new(detect_bot),
                Box::new(detect_server),
                Box::new(detect_iot),
                Box::new(detect_dns_profiler),
                Box::new(detect_beacon),
                Box::new(detect_scanner),
                Box::new(detect_streaming),
                Box::new(detect_cloud_sync),
                Box::new(detect_vpn),
                Box::new(detect_tor),
                Box::new(detect_game),
            ];

            for detector in &detectors {
                if let Some(f) = detector(profile) {
                    ip_findings.push(f);
                }
            }

            if let Some(f) = detect_lateral_movement(profile, &all_profiles) {
                ip_findings.push(f);
            }
            if let Some(f) = detect_data_exfil(profile) {
                ip_findings.push(f);
            }
            if let Some(f) = detect_c2_beacon(profile) {
                ip_findings.push(f);
            }
            if let Some(f) = detect_network_recon(profile) {
                ip_findings.push(f);
            }
            if let Some(f) = detect_printers_iot(profile, devices) {
                ip_findings.push(f);
            }

            if ip_findings.is_empty() {
                ip_findings.push(Finding {
                    ip: profile.ip.clone(),
                    kind: FindingKind::Unknown,
                    confidence: 0.0,
                    detail: format!("{} pkts, {} out, {} in, {} dns, {} domains",
                        profile.packet_count, profile.outbound_count,
                        profile.inbound_count, profile.dns_count, profile.dns_domains.len()),
                    indicators: vec![],
                });
            }

            findings.extend(ip_findings);
        }

        findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        findings
    }

    pub fn profiles(&self) -> &HashMap<String, IpProfile> { &self.profiles }
    pub fn packet_count(&self) -> usize { self.packets.len() }

    pub fn cross_reference(&self, devices: &[(String, Option<String>, Option<String>, Option<String>, Option<String>, String)]) -> String {
        let mut lines = Vec::new();

        for (ip, _mac, hostname, vendor, os_guess, ports) in devices {
            let hostname_str = hostname.as_deref().unwrap_or("unknown");
            let os_str = os_guess.as_deref().unwrap_or("OS unknown");
            let vendor_str = vendor.as_deref().unwrap_or("unknown vendor");

            if let Some(profile) = self.profiles.get(ip) {
                let duration = profile.last_seen - profile.first_seen;
                let pps = if duration > 0.0 { profile.packet_count as f64 / duration } else { 0.0 };

                let mut domain_vec: Vec<_> = profile.dns_domains.iter().collect();
                domain_vec.sort_by(|a, b| b.1.cmp(a.1));
                let top_domains: Vec<_> = domain_vec.iter()
                    .take(5)
                    .map(|(d, c)| format!("{}({})", d, c))
                    .collect();

                let mut port_vec: Vec<_> = profile.dest_ports.iter().collect();
                port_vec.sort_by(|a, b| b.1.cmp(a.1));
                let top_ports: Vec<_> = port_vec.iter()
                    .take(5)
                    .map(|(p, c)| format!("{}/{}", p, c))
                    .collect();

                let mut src_vec: Vec<_> = profile.src_ips.iter().collect();
                src_vec.sort_by(|a, b| b.1.cmp(a.1));
                let top_srcs: Vec<_> = src_vec.iter()
                    .take(3)
                    .map(|(ip, c)| format!("{}({})", ip, c))
                    .collect();

                lines.push(format!(
                    "Device at {} ({}, {}, {}) — {} packets over {:.1}s ({:.1} pps), {} out / {} in, {} TCP, {} UDP\n\
                     ️  DNS: {} domains [{}]\n\
                     ️  Dest ports: [{}]\n\
                     ️  Top sources: [{}]",
                    ip, hostname_str, os_str, vendor_str,
                    profile.packet_count, duration, pps, profile.outbound_count, profile.inbound_count,
                    profile.tcp_count, profile.udp_count,
                    profile.dns_domains.len(),
                    top_domains.join(", "),
                    top_ports.join(", "),
                    top_srcs.join(", "),
                ));

                let open_tcp: Vec<_> = profile.src_ports.keys()
                    .filter(|p| **p < 1024)
                    .map(|p| p.to_string())
                    .collect();
                if !open_tcp.is_empty() {
                    lines.push(format!("  Listening on: {}", open_tcp.join(", ")));
                }

                let server_clients = profile.src_ips.len();
                if server_clients > 3 {
                    lines.push(format!("  Serving {} unique clients", server_clients));
                }
            } else {
                lines.push(format!(
                    "Device at {} ({}, {}, {}) — no traffic observed in capture",
                    ip, hostname_str, os_str, vendor_str,
                ));
                if !ports.is_empty() {
                    lines.push(format!("  Open ports: {}", ports));
                }
            }
        }

        lines.join("\n")
    }
}

// ══════════════════════════════════════════════════════════════
// Real-Time Sliding Window
// ══════════════════════════════════════════════════════════════

pub struct RealtimeEngine {
    correlator: Correlator,
    window: Duration,
    packet_buffer: VecDeque<Packet>,
    last_analysis: Instant,
    pub min_interval: Duration,
}

impl RealtimeEngine {
    pub fn new(window_secs: u64) -> Self {
        Self {
            correlator: Correlator::new(),
            window: Duration::from_secs(window_secs),
            packet_buffer: VecDeque::new(),
            last_analysis: Instant::now(),
            min_interval: Duration::from_secs(5),
        }
    }

    pub fn ingest(&mut self, pkt: Packet) {
        self.packet_buffer.push_back(pkt.clone());
        self.correlator.ingest_packet(pkt);

        // Evict old packets from buffer
        let cutoff = self.current_time() - self.window.as_secs_f64();
        while let Some(front) = self.packet_buffer.front() {
            if front.epoch < cutoff {
                self.packet_buffer.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn should_analyze(&self) -> bool {
        self.last_analysis.elapsed() >= self.min_interval
    }

    pub fn analyze(&mut self) -> Vec<Finding> {
        self.last_analysis = Instant::now();
        self.correlator.correlate()
    }

    pub fn analyze_window(&mut self) -> Vec<Finding> {
        // Build correlator from just the window
        let mut window_corr = Correlator::new();
        for pkt in &self.packet_buffer {
            window_corr.ingest_packet(pkt.clone());
        }
        window_corr.correlate()
    }

    pub fn profiles(&self) -> &HashMap<String, IpProfile> {
        self.correlator.profiles()
    }

    pub fn packet_count(&self) -> usize {
        self.correlator.packet_count()
    }

    pub fn window_size(&self) -> usize {
        self.packet_buffer.len()
    }

    fn current_time(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }
}

// ══════════════════════════════════════════════════════════════
// Ollama AI Integration
// ══════════════════════════════════════════════════════════════

pub struct OllamaClient {
    base_url: String,
    model: String,
}

impl OllamaClient {
    pub fn new(model: &str) -> Self {
        Self { base_url: "http://localhost:11434".into(), model: model.to_string() }
    }

    pub fn is_available(&self) -> bool {
        reqwest::blocking::get(format!("{}/api/tags", self.base_url))
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Try to start Ollama in the background. Returns true if started successfully.
    pub fn try_start() -> bool {
        use std::process::Command;
        // Check if already running
        if reqwest::blocking::get("http://localhost:11434/api/tags").map(|r| r.status().is_success()).unwrap_or(false) {
            return true;
        }
        // Try launching ollama serve in background
        let _ = Command::new("ollama").arg("serve")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        // Wait up to 5 seconds for it to come up
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if reqwest::blocking::get("http://localhost:11434/api/tags")
                .map(|r| r.status().is_success())
                .unwrap_or(false) {
                return true;
            }
        }
        false
    }

    pub fn generate(&self, prompt: &str) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;

        let body = json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.3,
                "num_predict": 2048,
            }
        });

        let resp = client.post(format!("{}/api/generate", self.base_url))
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;

        let data: Value = resp.json().map_err(|e| e.to_string())?;
        Ok(data["response"].as_str().unwrap_or("(no response)").to_string())
    }

    pub fn analyze_findings(&self, findings: &[Finding], profiles: &HashMap<String, IpProfile>) -> String {
        let findings_json: Vec<Value> = findings.iter().map(|f| {
            let profile = profiles.get(&f.ip);
            json!({
                "ip": f.ip,
                "type": f.kind.to_string(),
                "confidence": format!("{:.0}%", f.confidence * 100.0),
                "detail": f.detail,
                "indicators": f.indicators,
                "packets": profile.map(|p| p.packet_count),
                "unique_destinations": profile.map(|p| p.dest_ips.len()),
                "unique_sources": profile.map(|p| p.src_ips.len()),
                "dns_domains": profile.map(|p| p.dns_domains.len()),
            })
        }).collect();

        let findings_str = serde_json::to_string_pretty(&findings_json).unwrap_or_default();

        let prompt = format!(
            "You are a network security analyst. Analyze these network traffic findings and provide:\n\
             1. A threat assessment for each identified device\n\
             2. Any suspicious patterns or anomalies\n\
             3. Recommendations for investigation\n\
             4. An overall network health summary\n\n\
             ## Findings\n{}\n\n\
             Provide your analysis in clear, concise language. Format as a report.",
            findings_str
        );

        self.generate(&prompt).unwrap_or_else(|e| format!("[AI unavailable: {}]", e))
    }

    pub fn explain_ip(&self, ip: &str, profile: &IpProfile, findings: &[Finding]) -> String {
        let ip_findings: Vec<&Finding> = findings.iter().filter(|f| f.ip == ip).collect();

        let prompt = format!(
            "Explain what this IP address is doing on the network based on these observations:\n\n\
             IP: {}\n\
             Packets: {} ({} outbound, {} inbound)\n\
             Duration: {:.1}s\n\
             Protocols: {} TCP, {} UDP, {} DNS\n\
             Unique destinations: {}\n\
             Unique sources: {}\n\
             DNS domains resolved: {}\n\
             Top domains: {}\n\
             Top destination ports: {}\n\n\
             Detector findings:\n{}\n\n\
             Provide a plain-English explanation of this device's behavior and purpose on the network.",
            ip,
            profile.packet_count, profile.outbound_count, profile.inbound_count,
            profile.last_seen - profile.first_seen,
            profile.tcp_count, profile.udp_count, profile.dns_count,
            profile.dest_ips.len(), profile.src_ips.len(), profile.dns_domains.len(),
            profile.dns_domains.iter().take(5).map(|(d, c)| format!("{}({})", d, c)).collect::<Vec<_>>().join(", "),
            profile.dest_ports.iter().take(5).map(|(p, c)| format!("{}({})", p, c)).collect::<Vec<_>>().join(", "),
            ip_findings.iter().map(|f| format!("- {} ({}%): {}", f.kind, (f.confidence * 100.0) as u32, f.detail)).collect::<Vec<_>>().join("\n"),
        );

        self.generate(&prompt).unwrap_or_else(|e| format!("[AI unavailable: {}]", e))
    }

    pub fn threat_summary(&self, findings: &[Finding]) -> String {
        let threat_ips: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::Bot | FindingKind::Scanner | FindingKind::Beacon | FindingKind::Tor))
            .collect();

        if threat_ips.is_empty() {
            return "No significant threats detected.".to_string();
        }

        let list: String = threat_ips.iter().map(|f|
            format!("- {} [{}] ({}%): {}", f.ip, f.kind, (f.confidence * 100.0) as u32, f.detail)
        ).collect::<Vec<_>>().join("\n");

        let prompt = format!(
            "You are a SOC analyst. These network devices show potentially malicious behavior:\n\n{}\n\n\
             Provide:\n\
             1. Severity assessment (Critical/High/Medium/Low) for each\n\
             2. Likely threat type\n\
             3. Recommended immediate actions\n\
             4. Whether these could be false positives\n\n\
             Be concise and actionable.",
            list
        );

        self.generate(&prompt).unwrap_or_else(|e| format!("[AI unavailable: {}]", e))
    }

    pub fn generate_report(
        &self,
        findings: &[Finding],
        profiles: &HashMap<String, IpProfile>,
        devices: &[(String, Option<String>, Option<String>, Option<String>, Option<String>, String)],
        nmap_summaries: &[String],
        cross_ref: &str,
    ) -> String {
        let total_packets: u64 = profiles.values().map(|p| p.packet_count).sum();
        let unique_ips = profiles.len();
        let total_dns: usize = profiles.values().map(|p| p.dns_domains.len()).sum();
        let unique_connections: usize = profiles.values().map(|p| p.sessions.len()).sum();

        let duration = if let Some((min, max)) = profiles.values()
            .map(|p| (p.first_seen, p.last_seen))
            .reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)))
        { max - min } else { 0.0 };

        let mut top_talkers: Vec<_> = profiles.values().collect();
        top_talkers.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
        let top_talkers_str: Vec<_> = top_talkers.iter().take(15).map(|p| {
            let dns = if p.dns_domains.is_empty() { String::new() } else {
                let mut d: Vec<_> = p.dns_domains.iter().collect();
                d.sort_by(|a, b| b.1.cmp(a.1));
                format!(", dns: {}", d.iter().take(3).map(|(d, c)| format!("{}({})", d, c)).collect::<Vec<_>>().join(", "))
            };
            let ports = if p.dest_ports.is_empty() { String::new() } else {
                let mut pp: Vec<_> = p.dest_ports.iter().collect();
                pp.sort_by(|a, b| b.1.cmp(a.1));
                format!(", ports: {}", pp.iter().take(3).map(|(p, c)| format!("{}/{}", p, c)).collect::<Vec<_>>().join(", "))
            };
            format!("  {}: {} pkts ({}↑ {}↓){}{}", p.ip, p.packet_count, p.outbound_count, p.inbound_count, dns, ports)
        }).collect();

        let mut all_domains: Vec<(&String, &u64)> = profiles.values()
            .flat_map(|p| p.dns_domains.iter())
            .collect();
        all_domains.sort_by(|a, b| b.1.cmp(a.1));
        let top_domains_str: Vec<_> = all_domains.iter().take(20).map(|(d, c)| format!("  {} — {}x", d, c)).collect();

        let mut all_conns: Vec<_> = profiles.values()
            .flat_map(|p| p.sessions.values())
            .collect();
        all_conns.sort_by(|a, b| b.pkt_count.cmp(&a.pkt_count));
        let top_conns_str: Vec<_> = all_conns.iter().take(15).map(|s| {
            format!("  {}:{} → {}:{} ({} pkts)", s.src, s.src_port, s.dst, s.dst_port, s.pkt_count)
        }).collect();

        let findings_str: Vec<_> = findings.iter().take(30).map(|f| {
            format!("  {} [{}] {}%: {}", f.ip, f.kind, (f.confidence * 100.0) as u32, f.detail)
        }).collect();

        let nmap_str = if nmap_summaries.is_empty() {
            "(no nmap scan data)".to_string()
        } else {
            nmap_summaries.join("\n")
        };

        let prompt = format!(
            "You are a senior network security analyst with full visibility into this network. You have been given COMPLETE data from both nmap scanning and live traffic capture.\n\n\
             ## Your Data\n\
             - {} devices discovered via nmap scanning\n\
             - {} packets captured over {:.1} seconds\n\
             - {} unique IPs communicating\n\
             - {} DNS domains resolved\n\
             - {} distinct TCP/UDP connections observed\n\n\
             ## Known Devices (from nmap)\n{}\n\n\
             ## Traffic Patterns\n\
             ### Top Talkers\n{}\n\n\
             ### Top DNS Domains\n{}\n\n\
             ### Most Active Connections\n{}\n\n\
             ## Detected Anomalies\n{}\n\n\
             ## Cross-Reference Analysis\n{}\n\n\
             ## Your Mission\n\
             Analyze this network comprehensively. You are looking for:\n\n\
             1. **Device Inventory**: What is every device? Role? Trust level?\n\
             2. **Communication Patterns**: Who talks to whom? What's normal vs abnormal?\n\
             3. **DNS Intelligence**: What domains are being resolved? Any suspicious? DGA patterns?\n\
             4. **Temporal Patterns**: When is traffic happening? Any off-hours activity? Periodic beacons?\n\
             5. **Service Analysis**: What services are running? Any unexpected?\n\
             6. **Anomaly Assessment**: Rate each anomaly. False positive or real threat?\n\
             7. **Network Topology**: Map the network. What's the structure?\n\
             8. **Security Recommendations**: What should the admin do?\n\n\
             Be thorough. Cross-reference everything. Don't just list findings — INTERPRET them.\n\
             What story does this network data tell? What is happening on this network right now?",
            devices.len(),
            total_packets, duration,
            unique_ips,
            total_dns,
            unique_connections,
            nmap_str,
            top_talkers_str.join("\n"),
            top_domains_str.join("\n"),
            top_conns_str.join("\n"),
            findings_str.join("\n"),
            cross_ref,
        );

        self.generate(&prompt).unwrap_or_else(|e| format!("[AI unavailable: {}]", e))
    }
}

// ══════════════════════════════════════════════════════════════
// Database Loader
// ══════════════════════════════════════════════════════════════

pub fn load_from_db(conn: &Connection) -> Vec<Packet> {
    let mut stmt = conn
        .prepare("SELECT epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query FROM packets ORDER BY epoch")
        .expect("Failed to prepare query");

    stmt.query_map([], |row| {
        Ok(Packet {
            epoch: row.get(0)?,
            ip_src: row.get(1)?,
            ip_dst: row.get(2)?,
            tcp_src_port: row.get(3)?,
            tcp_dst_port: row.get(4)?,
            udp_src_port: row.get(5)?,
            udp_dst_port: row.get(6)?,
            dns_query: row.get(7)?,
        })
    }).expect("Failed to query packets")
    .filter_map(|r| r.ok())
    .collect()
}

// ══════════════════════════════════════════════════════════════
// Pretty Print
// ══════════════════════════════════════════════════════════════

pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("(no findings)");
        return;
    }

    let mut by_kind: HashMap<FindingKind, Vec<&Finding>> = HashMap::new();
    for f in findings { by_kind.entry(f.kind.clone()).or_default().push(f); }

    let order = [
        FindingKind::Server, FindingKind::Browser, FindingKind::Bot,
        FindingKind::Scanner, FindingKind::Beacon, FindingKind::C2Beacon,
        FindingKind::LateralMovement, FindingKind::DataExfil, FindingKind::NetworkRecon,
        FindingKind::Tor, FindingKind::VPN,
        FindingKind::IoTDevice, FindingKind::PrinterIoT, FindingKind::IoTCoordinator,
        FindingKind::DNSProfiler, FindingKind::StreamingMedia,
        FindingKind::CloudSync, FindingKind::GameClient, FindingKind::Unknown,
    ];

    for kind in &order {
        if let Some(group) = by_kind.get(kind) {
            println!("\n── {:?} ({}) ──", kind, group.len());
            for f in group {
                let pct = (f.confidence * 100.0) as u32;
                let _bar = "█".repeat((f.confidence * 10.0) as usize);
                println!("  {:<16} [{}%] {}", f.ip, pct, f.detail);
                if !f.indicators.is_empty() {
                    for ind in f.indicators.iter().take(3) {
                        println!("  {:<16}      → {}", "", ind);
                    }
                }
            }
        }
    }
}

pub fn print_profile(profile: &IpProfile) {
    let duration = profile.last_seen - profile.first_seen;
    let pps = if duration > 0.0 { profile.packet_count as f64 / duration } else { 0.0 };

    println!("═══ {} ═══", profile.ip);
    println!("  Packets:     {} ({} out, {} in)", profile.packet_count, profile.outbound_count, profile.inbound_count);
    println!("  Duration:    {:.1}s ({:.1} pps)", duration, pps);
    println!("  Protocols:   {} TCP, {} UDP, {} DNS", profile.tcp_count, profile.udp_count, profile.dns_count);
    println!("  Connections: {} unique IPs ({} src, {} dst)", profile.unique_connections, profile.src_ips.len(), profile.dest_ips.len());
    println!("  Sessions:    {}", profile.sessions.len());
    println!("  Port entropy: dst {:.2}, src {:.2}", profile.dest_port_entropy, profile.src_port_entropy);
    println!("  Burst score: {:.3}", profile.burst_score);

    if !profile.dns_domains.is_empty() {
        let mut domains: Vec<_> = profile.dns_domains.iter().collect();
        domains.sort_by(|a, b| b.1.cmp(a.1));
        println!("  DNS domains:");
        for (domain, count) in domains.iter().take(8) {
            println!("    {:>5}x  {}", count, domain);
        }
    }

    if !profile.dest_ports.is_empty() {
        let mut ports: Vec<_> = profile.dest_ports.iter().collect();
        ports.sort_by(|a, b| b.1.cmp(a.1));
        println!("  Dest ports:");
        for (port, count) in ports.iter().take(8) {
            println!("    {:>5}x  port {}", count, port);
        }
    }
}
