use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use crate::correlate::{Finding, FindingKind};
use crate::tools::sudo_cmd;

// ── Belief Categories ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BeliefCategory {
    Bot,
    IoT,
    Camera,
    Clean,
    Unknown,
}

impl std::fmt::Display for BeliefCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BeliefCategory::Bot => write!(f, "BOT"),
            BeliefCategory::IoT => write!(f, "IOT"),
            BeliefCategory::Camera => write!(f, "CAM"),
            BeliefCategory::Clean => write!(f, "CLN"),
            BeliefCategory::Unknown => write!(f, "UNK"),
        }
    }
}

const ALL_CATEGORIES: [BeliefCategory; 5] = [
    BeliefCategory::Bot,
    BeliefCategory::IoT,
    BeliefCategory::Camera,
    BeliefCategory::Clean,
    BeliefCategory::Unknown,
];

// ── IP Belief ──

#[derive(Debug, Clone)]
pub struct IpBelief {
    pub ip: String,
    pub distribution: HashMap<BeliefCategory, f64>,
    pub entropy: f64,
    pub max_category: BeliefCategory,
    pub max_prob: f64,
    pub scanned: bool,
    pub scan_count: u32,
}

// ── Scanner Events ──

#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub is_alive: bool,
    pub open_ports: Vec<u32>,
    pub os_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ScannerEvent {
    ScanStarted { ip: String, tool: String },
    ScanComplete { ip: String, result: ScanSummary },
}

// ── Belief System ──

pub struct BeliefSystem {
    beliefs: HashMap<String, IpBelief>,
}

impl BeliefSystem {
    pub fn new() -> Self {
        BeliefSystem {
            beliefs: HashMap::new(),
        }
    }

    pub fn initialize_from_findings(&mut self, findings: &[Finding]) {
        for finding in findings {
            let primary_cat = finding_kind_to_category(&finding.kind);
            let primary_prob = finding.confidence * 0.8;
            let residual = 1.0 - primary_prob;
            let unknown_prob = residual * 0.4;
            let other_count = 3;
            let other_prob = if other_count > 0 && (residual - unknown_prob) > 0.0 {
                (residual - unknown_prob) / other_count as f64
            } else {
                0.0
            };

            let mut distribution = HashMap::new();
            for cat in &ALL_CATEGORIES {
                let p = if *cat == primary_cat {
                    primary_prob
                } else if *cat == BeliefCategory::Unknown {
                    unknown_prob
                } else {
                    other_prob
                };
                distribution.insert(*cat, p);
            }
            normalize_distribution(&mut distribution);

            let (max_cat, max_prob) = distribution
                .iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(c, p)| (*c, *p))
                .unwrap_or((BeliefCategory::Unknown, 0.0));
            let entropy = compute_entropy(&distribution);

            self.beliefs.insert(
                finding.ip.clone(),
                IpBelief {
                    ip: finding.ip.clone(),
                    distribution,
                    entropy,
                    max_category: max_cat,
                    max_prob,
                    scanned: false,
                    scan_count: 0,
                },
            );
        }
    }

    pub fn ensure_ip(&mut self, ip: &str) {
        if !self.beliefs.contains_key(ip) {
            let mut distribution = HashMap::new();
            for cat in &ALL_CATEGORIES {
                let p = match cat {
                    BeliefCategory::Clean => 0.50,
                    BeliefCategory::Unknown => 0.40,
                    _ => 0.025,
                };
                distribution.insert(*cat, p);
            }
            normalize_distribution(&mut distribution);
            let entropy = compute_entropy(&distribution);
            let (max_cat, max_prob) = distribution
                .iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(c, p)| (*c, *p))
                .unwrap_or((BeliefCategory::Unknown, 0.0));
            self.beliefs.insert(
                ip.to_string(),
                IpBelief {
                    ip: ip.to_string(),
                    distribution,
                    entropy,
                    max_category: max_cat,
                    max_prob,
                    scanned: false,
                    scan_count: 0,
                },
            );
        }
    }

    pub fn get_priority_ip(&self, max_scans: u32) -> Option<(String, f64)> {
        self.beliefs
            .values()
            .filter(|b| b.scan_count < max_scans && b.max_prob < 0.90)
            .max_by(|a, b| a.entropy.partial_cmp(&b.entropy).unwrap())
            .map(|b| (b.ip.clone(), b.entropy))
    }

    pub fn update_from_nmap(&mut self, ip: &str, is_alive: bool, open_ports: &[u32]) {
        if let Some(belief) = self.beliefs.get_mut(ip) {
            let mut dist = belief.distribution.clone();

            let iot_ports = [5353, 1900, 5355, 5683, 5684, 8883, 1883, 9100, 631];
            let cam_ports = [554, 1935, 8554, 1024, 1025];
            let has_iot = open_ports.iter().any(|p| iot_ports.contains(p));
            let has_camera = open_ports.iter().any(|p| cam_ports.contains(p));

            for cat in &ALL_CATEGORIES {
                let prob = dist.entry(*cat).or_insert(0.0);
                if is_alive && !open_ports.is_empty() {
                    match cat {
                        BeliefCategory::Clean => *prob *= 1.3,
                        BeliefCategory::IoT if has_iot => *prob *= 2.0,
                        BeliefCategory::Camera if has_camera => *prob *= 2.0,
                        _ => *prob *= 0.9,
                    }
                } else if is_alive {
                    match cat {
                        BeliefCategory::Unknown => *prob *= 1.2,
                        BeliefCategory::Clean => *prob *= 1.1,
                        _ => *prob *= 0.95,
                    }
                } else {
                    match cat {
                        BeliefCategory::Unknown => *prob *= 1.3,
                        BeliefCategory::Bot => *prob *= 0.8,
                        _ => *prob *= 1.0,
                    }
                }
            }

            normalize_distribution(&mut dist);
            belief.distribution = dist;
            belief.entropy = compute_entropy(&belief.distribution);
            let (max_cat, max_prob) = belief
                .distribution
                .iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                .map(|(c, p)| (*c, *p))
                .unwrap_or((BeliefCategory::Unknown, 0.0));
            belief.max_category = max_cat;
            belief.max_prob = max_prob;
            belief.scanned = true;
            belief.scan_count += 1;
        }
    }

    pub fn format_all(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut ips: Vec<&IpBelief> = self.beliefs.values().collect();
        ips.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap());

        for b in ips {
            let cats: Vec<String> = ALL_CATEGORIES
                .iter()
                .map(|cat| {
                    let p = b.distribution.get(cat).unwrap_or(&0.0);
                    format!("{}:{:.0}%", cat, p * 100.0)
                })
                .collect();

            let marker = if b.scanned {
                " 🔍"
            } else {
                ""
            };
            lines.push(format!(
                "  {:<16} {:>5.2} bits [{}]{}",
                b.ip,
                b.entropy,
                cats.join(", "),
                marker
            ));
        }

        lines.join("\n")
    }

    pub fn format_ip(&self, ip: &str) -> Option<String> {
        self.beliefs.get(ip).map(|b| {
            let cats: Vec<String> = ALL_CATEGORIES
                .iter()
                .map(|cat| {
                    let p = b.distribution.get(cat).unwrap_or(&0.0);
                    format!("{}: {:.0}%", cat, p * 100.0)
                })
                .collect();
            format!(
                "IP {}: entropy {:.2} bits [{}]{}",
                b.ip,
                b.entropy,
                cats.join(", "),
                if b.scanned { " (scanned)" } else { "" }
            )
        })
    }

    pub fn len(&self) -> usize {
        self.beliefs.len()
    }

    pub fn has(&self, ip: &str) -> bool {
        self.beliefs.contains_key(ip)
    }

    pub fn get_ip(&self, ip: &str) -> Option<&IpBelief> {
        self.beliefs.get(ip)
    }
}

// ── Helpers ──

fn compute_entropy(dist: &HashMap<BeliefCategory, f64>) -> f64 {
    let mut e = 0.0;
    for p in dist.values() {
        if *p > 0.0 {
            e -= p * p.log2();
        }
    }
    e
}

fn normalize_distribution(dist: &mut HashMap<BeliefCategory, f64>) {
    let sum: f64 = dist.values().sum();
    if sum > 0.0 {
        for v in dist.values_mut() {
            *v /= sum;
        }
    }
}

fn finding_kind_to_category(kind: &FindingKind) -> BeliefCategory {
    match kind {
        FindingKind::Bot
        | FindingKind::C2Beacon
        | FindingKind::Beacon
        | FindingKind::Scanner
        | FindingKind::LateralMovement
        | FindingKind::NetworkRecon
        | FindingKind::DataExfil
        | FindingKind::DNSProfiler => BeliefCategory::Bot,

        FindingKind::IoTDevice | FindingKind::PrinterIoT => BeliefCategory::IoT,

        FindingKind::Browser
        | FindingKind::Server
        | FindingKind::StreamingMedia
        | FindingKind::CloudSync
        | FindingKind::GameClient => BeliefCategory::Clean,

        FindingKind::VPN | FindingKind::Tor | FindingKind::IoTCoordinator | FindingKind::Unknown => {
            BeliefCategory::Unknown
        }
    }
}

pub fn ping_sweep(ip: &str) -> bool {
    let output = sudo_cmd("nmap")
        .args(["-sn", "-T5", "--max-retries", "1", "--host-timeout", "5s", ip])
        .output();
    match output {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            out.contains("Host is up")
        }
        Err(_) => false,
    }
}

pub fn version_scan(ip: &str) -> Vec<u32> {
    let output = sudo_cmd("nmap")
        .args([
            "-sV",
            "--top-ports",
            "100",
            "--open",
            "-oX",
            "-",
            "-T4",
            "--min-rate",
            "1000",
            ip,
        ])
        .output();
    match output {
        Ok(o) => {
            let xml = String::from_utf8_lossy(&o.stdout);
            extract_ports_from_xml(&xml)
        }
        Err(_) => Vec::new(),
    }
}

pub fn os_scan(ip: &str) -> Option<String> {
    let output = sudo_cmd("nmap")
        .args(["-O", "--open", "-oX", "-", "-T4", "--min-rate", "1000", ip])
        .output();
    match output {
        Ok(o) => {
            let xml = String::from_utf8_lossy(&o.stdout);
            extract_os_from_xml(&xml)
        }
        Err(_) => None,
    }
}

fn extract_os_from_xml(xml: &str) -> Option<String> {
    for line in xml.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<osmatch") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    let name = rest[..end].to_string();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

fn extract_ports_from_xml(xml: &str) -> Vec<u32> {
    let mut ports = Vec::new();
    for line in xml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("<port ") {
            if let Some(start) = trimmed.find("portid=\"") {
                let rest = &trimmed[start + 8..];
                if let Some(end) = rest.find('"') {
                    if let Ok(p) = rest[..end].parse::<u32>() {
                        ports.push(p);
                    }
                }
            }
        }
    }
    ports
}

// ── Scanner Thread ──

pub fn start_scanner(
    beliefs: Arc<Mutex<BeliefSystem>>,
    tx: mpsc::Sender<ScannerEvent>,
    _interface: String,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let interval = std::time::Duration::from_secs(4);
        loop {
            std::thread::sleep(interval);

            let target = {
                let sys = beliefs.lock().unwrap();
                sys.get_priority_ip(3)
            };

            if let Some((ip, _entropy)) = target {
                if tx
                    .send(ScannerEvent::ScanStarted {
                        ip: ip.clone(),
                        tool: "nmap".into(),
                    })
                    .is_err()
                {
                    break;
                }

                let is_alive = ping_sweep(&ip);

                let open_ports = if is_alive { version_scan(&ip) } else { Vec::new() };

                let os_hint: Option<String> = if is_alive && !open_ports.is_empty() {
                    Some(guess_os_from_ports(&open_ports))
                } else {
                    None
                };

                {
                    let mut sys = beliefs.lock().unwrap();
                    sys.update_from_nmap(&ip, is_alive, &open_ports);
                }

                if tx
                    .send(ScannerEvent::ScanComplete {
                        ip,
                        result: ScanSummary {
                            is_alive,
                            open_ports,
                            os_hint,
                        },
                    })
                    .is_err()
                {
                    break;
                }
            }
        }
    })
}

pub fn guess_os_from_ports(ports: &[u32]) -> String {
    if ports.contains(&9100) || ports.contains(&631) {
        "printer/IoT".into()
    } else if ports.contains(&554) || ports.contains(&1935) {
        "camera/streaming".into()
    } else if ports.contains(&22) && ports.contains(&443) && ports.contains(&80) {
        "Linux server".into()
    } else if ports.contains(&3389) {
        "Windows".into()
    } else if ports.contains(&8443) && ports.contains(&500) {
        "VPN/firewall appliance".into()
    } else {
        format!("{} open port(s)", ports.len())
    }
}
