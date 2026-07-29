use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

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
    stealth_level: u8,
) -> ScannerHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let handle = std::thread::spawn(move || {
        use crate::constants;
        if !constants::background_scanner_enabled(stealth_level) {
            return;
        }
        let interval = std::time::Duration::from_secs(constants::background_scanner_interval(stealth_level));
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(interval);

            if stop_clone.load(Ordering::Relaxed) {
                break;
            }

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
    });

    ScannerHandle { stop, _handle: handle }
}

pub struct ScannerHandle {
    stop: Arc<AtomicBool>,
    _handle: std::thread::JoinHandle<()>,
}

impl ScannerHandle {
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for ScannerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn guess_os_from_ports(ports: &[u32]) -> String {
    let has = |p: u32| ports.contains(&p);

    if has(9100) || has(631) {
        "printer/IoT".into()
    } else if has(554) || has(1935) {
        "camera/streaming".into()
    } else if has(22) && has(443) && has(80) {
        "Linux server".into()
    } else if has(3389) || has(5985) || has(5986) {
        "Windows".into()
    } else if has(445) && (has(135) || has(139)) {
        "Windows (SMB/RPC)".into()
    } else if has(88) && has(3268) {
        "Windows Domain Controller".into()
    } else if has(8443) && has(500) {
        "VPN/firewall appliance".into()
    } else if has(22) && has(443) {
        "Linux/Unix server".into()
    } else if has(22) {
        "Linux/Unix (SSH)".into()
    } else if has(443) || has(80) {
        "web server".into()
    } else {
        format!("{} open port(s)", ports.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_os_printer() {
        assert_eq!(guess_os_from_ports(&[9100, 80]), "printer/IoT");
        assert_eq!(guess_os_from_ports(&[631]), "printer/IoT");
    }

    #[test]
    fn test_guess_os_camera() {
        assert_eq!(guess_os_from_ports(&[554, 80]), "camera/streaming");
        assert_eq!(guess_os_from_ports(&[1935]), "camera/streaming");
    }

    #[test]
    fn test_guess_os_linux_server() {
        assert_eq!(guess_os_from_ports(&[22, 80, 443]), "Linux server");
    }

    #[test]
    fn test_guess_os_windows() {
        assert_eq!(guess_os_from_ports(&[3389, 445]), "Windows");
        assert_eq!(guess_os_from_ports(&[5985]), "Windows");
        assert_eq!(guess_os_from_ports(&[5986]), "Windows");
    }

    #[test]
    fn test_guess_os_windows_smb() {
        assert_eq!(guess_os_from_ports(&[445, 135]), "Windows (SMB/RPC)");
        assert_eq!(guess_os_from_ports(&[445, 139]), "Windows (SMB/RPC)");
    }

    #[test]
    fn test_guess_os_domain_controller() {
        assert_eq!(guess_os_from_ports(&[88, 3268, 445]), "Windows Domain Controller");
    }

    #[test]
    fn test_guess_os_vpn_firewall() {
        assert_eq!(guess_os_from_ports(&[8443, 500]), "VPN/firewall appliance");
    }

    #[test]
    fn test_guess_os_linux_server_only() {
        assert_eq!(guess_os_from_ports(&[22, 443]), "Linux/Unix server");
    }

    #[test]
    fn test_guess_os_linux_ssh() {
        assert_eq!(guess_os_from_ports(&[22]), "Linux/Unix (SSH)");
    }

    #[test]
    fn test_guess_os_web_server() {
        assert_eq!(guess_os_from_ports(&[443]), "web server");
        assert_eq!(guess_os_from_ports(&[80]), "web server");
    }

    #[test]
    fn test_guess_os_unknown() {
        let result = guess_os_from_ports(&[9999, 8888]);
        assert!(result.contains("2 open port(s)"), "should fallback to port count: {}", result);
    }

    #[test]
    fn test_guess_os_priority_printer_over_linux() {
        // Printer should take priority over Linux server
        assert_eq!(guess_os_from_ports(&[9100, 22, 80, 443]), "printer/IoT");
    }

    #[test]
    fn test_guess_os_empty() {
        assert_eq!(guess_os_from_ports(&[]), "0 open port(s)");
    }

    // ── BeliefSystem Tests ──

    #[test]
    fn test_belief_system_new_is_empty() {
        let sys = BeliefSystem::new();
        assert_eq!(sys.len(), 0);
        assert!(!sys.has("192.168.1.1"));
        assert!(sys.get_ip("192.168.1.1").is_none());
        assert!(sys.get_priority_ip(3).is_none());
    }

    #[test]
    fn test_belief_system_ensure_ip() {
        let mut sys = BeliefSystem::new();
        sys.ensure_ip("192.168.1.10");
        assert_eq!(sys.len(), 1);
        assert!(sys.has("192.168.1.10"));

        let belief = sys.get_ip("192.168.1.10").unwrap();
        assert!(belief.max_prob > 0.0);
        assert!(!belief.scanned);
        assert_eq!(belief.scan_count, 0);

        // ensure_ip again — should not duplicate
        sys.ensure_ip("192.168.1.10");
        assert_eq!(sys.len(), 1);
    }

    #[test]
    fn test_belief_system_initialize_from_findings() {
        let mut sys = BeliefSystem::new();
        let findings = vec![
            Finding { ip: "10.0.0.1".into(), kind: FindingKind::Browser, confidence: 0.8, detail: String::new(), indicators: vec![] },
            Finding { ip: "10.0.0.2".into(), kind: FindingKind::Scanner, confidence: 0.6, detail: String::new(), indicators: vec![] },
        ];
        sys.initialize_from_findings(&findings);
        assert_eq!(sys.len(), 2);

        let b1 = sys.get_ip("10.0.0.1").unwrap();
        assert!(b1.max_prob > 0.3, "Browser finding should push Clean probability high");

        let b2 = sys.get_ip("10.0.0.2").unwrap();
        assert!(b2.max_prob > 0.3, "Scanner finding should push Bot probability high");
    }

    #[test]
    fn test_belief_system_update_from_nmap_alive_with_ports() {
        let mut sys = BeliefSystem::new();
        sys.ensure_ip("192.168.1.50");
        let before = sys.get_ip("192.168.1.50").unwrap().max_prob;

        sys.update_from_nmap("192.168.1.50", true, &[22, 80, 443]);
        let after = sys.get_ip("192.168.1.50").unwrap();
        assert!(after.scanned);
        assert_eq!(after.scan_count, 1);
        assert!(after.max_prob > before || after.max_prob < before,
            "distribution should change after nmap update");
    }

    #[test]
    fn test_belief_system_update_from_nmap_dead() {
        let mut sys = BeliefSystem::new();
        sys.ensure_ip("192.168.1.99");
        sys.update_from_nmap("192.168.1.99", false, &[]);
        let belief = sys.get_ip("192.168.1.99").unwrap();
        assert!(belief.scanned);
        assert_eq!(belief.scan_count, 1);
    }

    #[test]
    fn test_belief_system_update_from_nmap_unknown_ip() {
        let mut sys = BeliefSystem::new();
        sys.update_from_nmap("10.99.99.99", true, &[80]);
        assert_eq!(sys.len(), 0, "updating unknown IP should not add it");
    }

    #[test]
    fn test_belief_system_get_priority_ip_entropy() {
        let mut sys = BeliefSystem::new();
        // Two IPs with different entropy — should pick higher entropy
        sys.ensure_ip("192.168.1.1");
        sys.ensure_ip("192.168.1.2");
        // Scan one to reduce its entropy (increase confidence)
        sys.update_from_nmap("192.168.1.1", true, &[22, 80, 443]);

        let priority = sys.get_priority_ip(3);
        assert!(priority.is_some());
        let (ip, _entropy) = priority.unwrap();
        assert_eq!(ip, "192.168.1.2", "unscanned IP should have higher entropy and be prioritized");
    }

    #[test]
    fn test_belief_system_get_priority_ip_max_scans_exceeded() {
        let mut sys = BeliefSystem::new();
        sys.ensure_ip("192.168.1.1");
        sys.update_from_nmap("192.168.1.1", true, &[22]);
        sys.update_from_nmap("192.168.1.1", true, &[22]);
        sys.update_from_nmap("192.168.1.1", true, &[22]);
        assert_eq!(sys.get_ip("192.168.1.1").unwrap().scan_count, 3);
        // max_scans=3 means scan_count < 3 is the filter — so 3 scans means excluded
        assert!(sys.get_priority_ip(3).is_none());
    }

    #[test]
    fn test_belief_system_format_all() {
        let mut sys = BeliefSystem::new();
        sys.ensure_ip("192.168.1.10");
        sys.ensure_ip("192.168.1.20");
        let output = sys.format_all();
        assert!(output.contains("192.168.1.10"));
        assert!(output.contains("192.168.1.20"));
        assert!(output.contains("bits"));
    }

    #[test]
    fn test_belief_system_format_ip() {
        let mut sys = BeliefSystem::new();
        sys.ensure_ip("10.0.0.5");
        let output = sys.format_ip("10.0.0.5").unwrap();
        assert!(output.contains("10.0.0.5"));
        assert!(output.contains("entropy"));

        assert!(sys.format_ip("10.0.0.99").is_none());
    }

    #[test]
    fn test_compute_entropy() {
        let mut dist = HashMap::new();
        dist.insert(BeliefCategory::Clean, 1.0);
        assert_eq!(compute_entropy(&dist), 0.0, "deterministic distribution should have zero entropy");

        let mut dist2 = HashMap::new();
        dist2.insert(BeliefCategory::Bot, 0.5);
        dist2.insert(BeliefCategory::Clean, 0.5);
        let e = compute_entropy(&dist2);
        assert!(e > 0.9 && e < 1.1, "50/50 split should have ~1.0 bit of entropy, got {}", e);
    }

    #[test]
    fn test_normalize_distribution() {
        let mut dist = HashMap::new();
        dist.insert(BeliefCategory::Bot, 3.0);
        dist.insert(BeliefCategory::Clean, 7.0);
        normalize_distribution(&mut dist);
        let sum: f64 = dist.values().sum();
        assert!((sum - 1.0).abs() < 0.001, "normalized distribution should sum to 1.0, got {}", sum);
    }

    #[test]
    fn test_finding_kind_to_category() {
        assert_eq!(finding_kind_to_category(&FindingKind::Bot), BeliefCategory::Bot);
        assert_eq!(finding_kind_to_category(&FindingKind::C2Beacon), BeliefCategory::Bot);
        assert_eq!(finding_kind_to_category(&FindingKind::Scanner), BeliefCategory::Bot);
        assert_eq!(finding_kind_to_category(&FindingKind::Browser), BeliefCategory::Clean);
        assert_eq!(finding_kind_to_category(&FindingKind::Server), BeliefCategory::Clean);
        assert_eq!(finding_kind_to_category(&FindingKind::IoTDevice), BeliefCategory::IoT);
        assert_eq!(finding_kind_to_category(&FindingKind::VPN), BeliefCategory::Unknown);
        assert_eq!(finding_kind_to_category(&FindingKind::Unknown), BeliefCategory::Unknown);
    }

    #[test]
    fn test_extract_ports_from_xml() {
        let xml = r#"<nmaprun>
  <host><ports>
    <port protocol="tcp" portid="22"><state state="open"/></port>
    <port protocol="tcp" portid="80"><state state="open"/></port>
    <port protocol="tcp" portid="443"><state state="open"/></port>
  </ports></host>
</nmaprun>"#;
        let ports = extract_ports_from_xml(xml);
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_extract_ports_from_xml_empty() {
        assert!(extract_ports_from_xml("").is_empty());
        assert!(extract_ports_from_xml("<nmaprun></nmaprun>").is_empty());
    }

    #[test]
    fn test_extract_os_from_xml() {
        let xml = r#"<nmaprun>
  <host><os>
    <osmatch name="Linux 5.4" accuracy="95"/>
  </os></host>
</nmaprun>"#;
        assert_eq!(extract_os_from_xml(xml), Some("Linux 5.4".into()));
    }

    #[test]
    fn test_extract_os_from_xml_none() {
        assert!(extract_os_from_xml("").is_none());
        assert!(extract_os_from_xml("<nmaprun></nmaprun>").is_none());
    }

    #[test]
    fn test_guess_os_priority_camera_over_printer() {
        assert_eq!(guess_os_from_ports(&[9100, 554, 1935]), "printer/IoT");
    }

    #[test]
    fn test_guess_os_vpn_only_8443() {
        // Port 8443 alone falls through to generic count (only 443/80 match "web server")
        let result = guess_os_from_ports(&[8443]);
        assert!(result.contains("1 open port(s)"), "8443 alone should not match web server: {}", result);
    }

    #[test]
    fn test_guess_os_single_domain_controller_port() {
        // Port 88 alone falls through (needs 88+3268 for domain controller)
        let result = guess_os_from_ports(&[88]);
        assert!(result.contains("1 open port(s)"), "port 88 alone should not match: {}", result);
    }
}
