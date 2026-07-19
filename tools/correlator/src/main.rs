#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::{json, Value};

mod correlate;
mod scanner;
use correlate::{Correlator, OllamaClient, load_from_db};
use scanner::{BeliefSystem, ScannerEvent, start_scanner};

static ALWAYS_ALLOW: AtomicBool = AtomicBool::new(false);
static BELIEFS: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<BeliefSystem>>> = std::sync::OnceLock::new();

// ── Config ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
struct Config {
    #[serde(default = "default_interface")]
    interface: String,
    #[serde(default = "default_target")]
    target: String,
    #[serde(default = "default_duration")]
    duration: u64,
    #[serde(default = "default_model")]
    model: String,
    #[serde(default = "default_save_path")]
    save_path: PathBuf,
    #[serde(default)]
    ai: AiConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct AiConfig {
    #[serde(default = "default_model")]
    model: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self { model: default_model(), enabled: true }
    }
}

fn default_interface() -> String { "en1".into() }
fn default_target() -> String { "192.168.1.0/24".into() }
fn default_duration() -> u64 { 300 }
fn default_model() -> String { "mistral".into() }
fn default_save_path() -> PathBuf { dirs().join("correlator") }
fn default_true() -> bool { true }

fn dirs() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".correlator"))
        .unwrap_or_else(|_| std::env::temp_dir().join("correlator"))
}

fn load_config() -> Config {
    let paths = [
        PathBuf::from("correlator.toml"),
        dirs().join("config.toml"),
        PathBuf::from("/etc/correlator/config.toml"),
    ];
    for p in &paths {
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(p) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return cfg;
                }
            }
        }
    }
    Config::default()
}

// ── CLI ──────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "correlator", version, about = "Network intelligence — scan, capture, interpret, chat")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Real-time packet interpretation — no AI, just smart TShark output
    LiveInterpret {
        /// Network interface (default: from config)
        #[arg(short, long)]
        interface: Option<String>,
        /// Capture duration in seconds
        #[arg(long)]
        duration: Option<u64>,
        /// Save capture to /tmp instead of default path
        #[arg(long)]
        no_save: bool,
        /// Output directory (default: ~/.correlator or from config)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Verbose output — show all packets
        #[arg(short, long)]
        verbose: bool,
        /// Include AI interpretation (requires Ollama)
        #[arg(long)]
        ai: bool,
        /// AI model to use
        #[arg(long)]
        model: Option<String>,
    },

    /// Capture packets + nmap scan in parallel, store metadata
    Capture {
        /// Network interface
        #[arg(short, long)]
        interface: Option<String>,
        /// CIDR target for nmap (e.g. 192.168.1.0/24)
        #[arg(short, long)]
        target: Option<String>,
        /// Capture duration in seconds
        #[arg(long)]
        duration: Option<u64>,
        /// Save capture to /tmp instead of default path
        #[arg(long)]
        no_save: bool,
        /// Output directory
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fast scan — skip OS/version detection
        #[arg(long)]
        fast: bool,
        /// Skip nmap scan
        #[arg(long)]
        no_nmap: bool,
        /// Skip tshark capture
        #[arg(long)]
        no_tshark: bool,
        /// Print raw tshark JSON to stderr
        #[arg(long)]
        debug: bool,
    },

    /// Chat with AI about captured network data
    Chat {
        /// Database file to resume from
        #[arg(short, long)]
        db: Option<PathBuf>,
        /// AI model
        #[arg(long)]
        model: Option<String>,
    },

    /// Run nmap scan only
    Scan {
        /// CIDR target
        #[arg(short, long)]
        target: Option<String>,
        /// Output database
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Search network data — no AI, just smart queries
    Search {
        /// Database file
        #[arg(short, long)]
        db: PathBuf,
        /// Search query (ip, port, dns, hostname, etc.)
        #[arg(short, long)]
        query: Option<String>,
    },

    /// Query captured packets with SQL
    Query {
        /// SQL query
        sql: String,
        /// Database file
        #[arg(short, long)]
        db: PathBuf,
    },

    /// Show traffic stats
    Stats {
        #[arg(short, long)]
        db: PathBuf,
    },

    /// List DNS queries
    Dns {
        #[arg(short, long)]
        db: PathBuf,
    },

    /// List top talkers
    TopTalkers {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },

    /// List known devices
    Devices {
        #[arg(short, long)]
        db: PathBuf,
    },

    /// Generate AI report
    Report {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(long)]
        model: Option<String>,
    },

    /// Ask AI a single question
    Ask {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(short, long)]
        question: String,
        #[arg(long)]
        model: Option<String>,
    },

    /// List saved capture databases
    List,
}

// ── Database ─────────────────────────────────────────────────

fn init_db(db_path: &Path) -> Connection {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(db_path).expect("Failed to open SQLite database");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch REAL, ip_src TEXT, ip_dst TEXT,
            tcp_src_port INTEGER, tcp_dst_port INTEGER,
            udp_src_port INTEGER, udp_dst_port INTEGER,
            dns_query TEXT, raw_json TEXT,
            frame_len INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_epoch ON packets(epoch);
        CREATE INDEX IF NOT EXISTS idx_src ON packets(ip_src);
        CREATE INDEX IF NOT EXISTS idx_dst ON packets(ip_dst);
        CREATE INDEX IF NOT EXISTS idx_dns ON packets(dns_query);"
    ).expect("Failed to create tables");
    // Migration: add frame_len to pre-existing databases
    conn.execute("ALTER TABLE packets ADD COLUMN frame_len INTEGER", []).ok();
    conn.execute_batch(
        "

        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            os_guess TEXT,
            ports TEXT,
            first_seen REAL,
            last_seen REAL,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS nmap_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_time REAL,
            raw_xml TEXT,
            summary TEXT
        );

        CREATE TABLE IF NOT EXISTS interpretations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch REAL,
            ip TEXT,
            role TEXT,
            detail TEXT,
            confidence REAL
        );"
    ).expect("Failed to create tables");
    conn
}

fn open_db(db_path: &Path) -> Connection {
    if !db_path.exists() {
        eprintln!("[Error] Database not found: {}", db_path.display());
        std::process::exit(1);
    }
    Connection::open(db_path).expect("Failed to open database")
}

fn default_db_path(no_save: bool, output: Option<&Path>) -> PathBuf {
    if let Some(p) = output {
        return p.to_path_buf();
    }
    if no_save {
        return std::env::temp_dir().join(format!("correlator_{}.db", chrono_suffix()));
    }
    let dir = dirs();
    std::fs::create_dir_all(&dir).ok();
    dir.join(format!("capture_{}.db", chrono_suffix()))
}

fn chrono_suffix() -> String {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().to_string()
}

// ── TShark Field Extractor ───────────────────────────────────

fn extract_fields(raw_line: &str) -> Option<(Option<f64>, Option<String>, Option<String>, Option<u32>, Option<u32>, Option<u32>, Option<u32>, Option<String>, Option<u32>)> {
    let val: Value = serde_json::from_str(raw_line).ok()?;
    let layers = val.get("_source")
        .and_then(|s| s.get("layers"))
        .or_else(|| val.get("layers"))
        .and_then(|l| l.as_object());
    let flat = if layers.is_none() { val.as_object() } else { None };

    let get_field = |name: &str| -> Option<&str> {
        let alt = name.replace('.', "_");
        let names: [&str; 2] = [name, &alt];
        if let Some(l) = &layers {
            for n in &names {
                if let Some(v) = l.get(*n) {
                    if let Some(s) = v.as_str() { return Some(s); }
                    if let Some(arr) = v.as_array() {
                        if let Some(first) = arr.first() {
                            if let Some(s) = first.as_str() { return Some(s); }
                        }
                    }
                }
            }
            None
        } else if let Some(f) = &flat {
            for n in &names {
                if let Some(v) = f.get(*n) {
                    if let Some(s) = v.as_str() { return Some(s); }
                    if let Some(arr) = v.as_array() {
                        if let Some(first) = arr.first() {
                            if let Some(s) = first.as_str() { return Some(s); }
                        }
                    }
                }
            }
            None
        } else {
            None
        }
    };

    Some((
        get_field("frame.time_epoch").and_then(|s| s.parse::<f64>().ok()),
        get_field("ip.src").map(|s| s.to_string()),
        get_field("ip.dst").map(|s| s.to_string()),
        get_field("tcp.srcport").and_then(|s| s.parse::<u32>().ok()),
        get_field("tcp.dstport").and_then(|s| s.parse::<u32>().ok()),
        get_field("udp.srcport").and_then(|s| s.parse::<u32>().ok()),
        get_field("udp.dstport").and_then(|s| s.parse::<u32>().ok()),
        get_field("dns.qry.name").map(|s| s.to_string()),
        get_field("frame.len").and_then(|s| s.parse::<u32>().ok()),
    ))
}

// ── Live Interpret ───────────────────────────────────────────

struct InterpretEngine {
    ip_roles: HashMap<String, IpRole>,
    dns_map: HashMap<String, Vec<String>>,
    port_map: HashMap<u16, &'static str>,
}

struct IpRole {
    role: String,
    detail: String,
    confidence: f64,
    ports: Vec<u16>,
    dns_queries: Vec<String>,
    packet_count: u64,
    first_seen: f64,
    last_seen: f64,
}

impl InterpretEngine {
    fn new() -> Self {
        let mut port_map = HashMap::new();
        // Well-known ports
        port_map.insert(22, "SSH");
        port_map.insert(23, "Telnet");
        port_map.insert(25, "SMTP");
        port_map.insert(53, "DNS");
        port_map.insert(80, "HTTP");
        port_map.insert(110, "POP3");
        port_map.insert(143, "IMAP");
        port_map.insert(443, "HTTPS");
        port_map.insert(445, "SMB");
        port_map.insert(993, "IMAPS");
        port_map.insert(995, "POP3S");
        port_map.insert(3306, "MySQL");
        port_map.insert(3389, "RDP");
        port_map.insert(5000, "UPnP/DLNA");
        port_map.insert(5353, "mDNS");
        port_map.insert(8008, "Chromecast");
        port_map.insert(8009, "Chromecast");
        port_map.insert(8080, "HTTP-Proxy");
        port_map.insert(8443, "HTTPS-Alt");
        port_map.insert(9100, "Printer");
        port_map.insert(5432, "PostgreSQL");
        port_map.insert(6379, "Redis");
        port_map.insert(27017, "MongoDB");

        Self {
            ip_roles: HashMap::new(),
            dns_map: HashMap::new(),
            port_map,
        }
    }

    fn process_packet(&mut self, epoch: f64, ip_src: &str, ip_dst: &str,
                      _tcp_src: Option<u16>, tcp_dst: Option<u16>,
                      _udp_src: Option<u16>, _udp_dst: Option<u16>,
                      dns_qry: Option<&str>) {
        // Skip broadcast/multicast
        if ip_dst.starts_with("224.") || ip_dst.starts_with("239.") || ip_dst == "255.255.255.255" {
            return;
        }
        if ip_src.starts_with("224.") || ip_src.starts_with("239.") {
            return;
        }

        // Process src IP
        {
            let src_role = self.ip_roles.entry(ip_src.to_string()).or_insert_with(|| IpRole {
                role: "unknown".into(),
                detail: String::new(),
                confidence: 0.0,
                ports: Vec::new(),
                dns_queries: Vec::new(),
                packet_count: 0,
                first_seen: epoch,
                last_seen: epoch,
            });
            src_role.packet_count += 1;
            src_role.last_seen = epoch;
            if let Some(port) = tcp_dst {
                if !src_role.ports.contains(&port) {
                    src_role.ports.push(port);
                }
            }
            if let Some(qry) = dns_qry {
                src_role.dns_queries.push(qry.to_string());
            }
        }

        // Process dst IP
        {
            let dst_role = self.ip_roles.entry(ip_dst.to_string()).or_insert_with(|| IpRole {
                role: "unknown".into(),
                detail: String::new(),
                confidence: 0.0,
                ports: Vec::new(),
                dns_queries: Vec::new(),
                packet_count: 0,
                first_seen: epoch,
                last_seen: epoch,
            });
            dst_role.packet_count += 1;
            dst_role.last_seen = epoch;

            // Track ports
            if let Some(port) = tcp_dst {
                if let Some(svc) = self.port_map.get(&port) {
                    dst_role.detail = format!("serves {} ({})", svc, port);
                    dst_role.confidence = 0.7;
                }
            }

            if let Some(qry) = dns_qry {
                dst_role.detail = format!("queries {}", qry);
                dst_role.confidence = 0.6;
            }
        }

        // Track DNS in map
        if let Some(qry) = dns_qry {
            self.dns_map.entry(ip_src.to_string()).or_default().push(qry.to_string());
        }
    }

    fn interpret(&self) -> Vec<(String, String)> {
        let mut interpretations = Vec::new();
        let mut sorted: Vec<_> = self.ip_roles.iter().collect();
        sorted.sort_by(|a, b| b.1.packet_count.cmp(&a.1.packet_count));

        for (ip, role) in sorted.iter().take(20) {
            let mut desc = format!("[{}]", ip);

            // Determine role from ports and behavior
            let has_80 = role.ports.contains(&80);
            let has_443 = role.ports.contains(&443);
            let has_22 = role.ports.contains(&22);
            let has_5353 = role.ports.contains(&5353);
            let has_8008 = role.ports.contains(&8008);
            let has_8009 = role.ports.contains(&8009);
            let has_5000 = role.ports.contains(&5000);
            let has_9100 = role.ports.contains(&9100);
            let dns_count = role.dns_queries.len();

            if has_80 || has_443 {
                if has_22 {
                    desc.push_str(" — server (HTTP + SSH)");
                } else {
                    desc.push_str(" — device on web");
                }
            } else if has_8008 || has_8009 {
                desc.push_str(" — Chromecast");
            } else if has_5353 {
                desc.push_str(" — mDNS device");
            } else if has_5000 {
                desc.push_str(" — UPnP/DLNA device");
            } else if has_9100 {
                desc.push_str(" — printer");
            } else if has_22 {
                desc.push_str(" — Linux/Mac device");
            } else if dns_count > 3 {
                desc.push_str(" — active browser");
            } else if role.packet_count > 100 {
                desc.push_str(" — high-traffic device");
            } else {
                desc.push_str(" — IoT/embedded");
            }

            // Add DNS context
            if !role.dns_queries.is_empty() {
                let unique_dns: Vec<String> = role.dns_queries.iter().cloned().collect::<std::collections::HashSet<_>>().into_iter().collect();
                desc.push_str(&format!(" | dns: {}", unique_dns.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
            }

            // Add packet count
            desc.push_str(&format!(" | {} pkts", role.packet_count));

            interpretations.push((ip.to_string(), desc));
        }

        interpretations
    }
}

fn run_live_interpret(interface: &str, duration: u64, no_save: bool, output: Option<&Path>, verbose: bool, use_ai: bool, model: &str) {
    println!("═══════ LIVE INTERPRET ═══════");
    println!("[System] Interface: {}", interface);
    println!("[System] Duration: {}s", duration);
    println!("[System] AI: {}", if use_ai { "enabled" } else { "disabled (use --ai to enable)" });
    println!("[System] Press 'q' to stop early\n");

    let db_path = default_db_path(no_save, output);
    let conn = init_db(&db_path);
    let conn = Arc::new(Mutex::new(conn));

    // Start tshark in background thread
    let tshark_args = vec![
        "-i", interface, "-n", "-l", "-T", "ek",
        "-f", "not host 127.0.0.1",
        "-e", "frame.time_epoch", "-e", "frame.len",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "dns.qry.name",
    ];

    let mut child = sudo_cmd("tshark").args(&tshark_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().expect("Failed to start tshark — is it installed?");

    let child_pid = child.id();

    // In AI mode, don't use a timer — run until user quits
    let timer_handle = if !use_ai {
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(duration));
            let _ = sudo_cmd("kill").args(["-INT", &child_pid.to_string()]).output();
        });
        Some(handle)
    } else {
        None
    };

    // If AI mode, spawn tshark reader in background and run chat loop
    if use_ai {
        // Take stdout before spawning thread
        let stdout = child.stdout.take().expect("Failed to take tshark stdout");

        // Spawn packet reader thread
        let conn_clone = conn.clone();
        let reader_handle = std::thread::spawn(move || {
            use std::io::BufRead;
            let mut engine = InterpretEngine::new();

            let reader = std::io::BufReader::new(stdout);
            for line_result in reader.lines() {
                if let Ok(raw_line) = line_result {
                    if raw_line.trim().is_empty() { continue; }
                    if raw_line.contains("\"index\"") && !raw_line.contains("\"_source\"") { continue; }

                    if let Some((epoch, ip_src, ip_dst, tcp_src, tcp_dst, udp_src, udp_dst, dns_qry, frame_len)) = extract_fields(&raw_line) {
                        if let (Some(ref src), Some(ref dst)) = (&ip_src, &ip_dst) {
                            engine.process_packet(
                                epoch.unwrap_or(0.0), src, dst,
                                tcp_src.map(|p| p as u16), tcp_dst.map(|p| p as u16),
                                udp_src.map(|p| p as u16), udp_dst.map(|p| p as u16),
                                dns_qry.as_deref(),
                            );
                            let c = conn_clone.lock().unwrap();
                            let _ = c.execute(
                                "INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json, frame_len) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                params![epoch, ip_src.as_deref(), ip_dst.as_deref(), tcp_src.map(|p| p as i32), tcp_dst.map(|p| p as i32), udp_src.map(|p| p as i32), udp_dst.map(|p| p as i32), dns_qry.as_deref(), raw_line.trim(), frame_len.map(|p| p as i32)]
                            );
                        }
                    }
                }
            }
        });

        // Run chat loop
        run_chat(&db_path, model, true);

        // Cleanup
        let _ = child.kill();
        let _ = reader_handle.join();
        // timer_handle is None in AI mode
    } else {
        // Original non-AI mode
        let mut engine = InterpretEngine::new();
        let mut packet_count: u64 = 0;
        let mut stored_count: u64 = 0;
        let start = Instant::now();

        use crossterm::event::{self, Event, KeyCode, KeyEventKind};
        use std::io::BufRead;

        crossterm::terminal::enable_raw_mode().ok();

        if let Some(stdout_stream) = child.stdout.take() {
            let reader = std::io::BufReader::new(stdout_stream);

            for line_result in reader.lines() {
                if event::poll(Duration::from_millis(0)).unwrap() {
                    if let Event::Key(key_event) = event::read().unwrap() {
                        if key_event.kind == KeyEventKind::Press {
                            match key_event.code {
                                KeyCode::Char('q') | KeyCode::Char('Q') => {
                                    println!("\r\x1b[K[System] Stopping early...");
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }

                match line_result {
                    Ok(raw_line) => {
                        if raw_line.trim().is_empty() { continue; }
                        if raw_line.contains("\"index\"") && !raw_line.contains("\"_source\"") { continue; }

                        if let Some((epoch, ip_src, ip_dst, tcp_src, tcp_dst, udp_src, udp_dst, dns_qry, frame_len)) = extract_fields(&raw_line) {
                            packet_count += 1;

                            if let (Some(ref src), Some(ref dst)) = (&ip_src, &ip_dst) {
                                engine.process_packet(
                                    epoch.unwrap_or(0.0), src, dst,
                                    tcp_src.map(|p| p as u16), tcp_dst.map(|p| p as u16),
                                    udp_src.map(|p| p as u16), udp_dst.map(|p| p as u16),
                                    dns_qry.as_deref(),
                                );

                                let c = conn.lock().unwrap();
                                let _ = c.execute(
                                    "INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json, frame_len) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                    params![epoch, ip_src.as_deref(), ip_dst.as_deref(), tcp_src.map(|p| p as i32), tcp_dst.map(|p| p as i32), udp_src.map(|p| p as i32), udp_dst.map(|p| p as i32), dns_qry.as_deref(), raw_line.trim(), frame_len.map(|p| p as i32)]
                                );
                                stored_count += 1;
                            }

                            if verbose || packet_count.is_multiple_of(10) {
                                let elapsed = start.elapsed().as_secs_f64();
                                if let Some(ref dns) = dns_qry {
                                    println!("\r\x1b[K  {:.1}s | {} → {} | DNS: {}", elapsed,
                                        ip_src.as_deref().unwrap_or("?"),
                                        ip_dst.as_deref().unwrap_or("?"),
                                        dns);
                                } else if let Some(port) = tcp_dst {
                                    let svc = engine.port_map.get(&(port as u16)).unwrap_or(&"?");
                                    println!("\r\x1b[K  {:.1}s | {} → {}:{} ({})", elapsed,
                                        ip_src.as_deref().unwrap_or("?"),
                                        ip_dst.as_deref().unwrap_or("?"),
                                        port, svc);
                                }
                            }

                            if packet_count.is_multiple_of(100) {
                                let elapsed = start.elapsed().as_secs();
                                print!("\r\x1b[K  {} pkts | {} stored | {}s elapsed  ",
                                    packet_count, stored_count, elapsed);
                                io::stdout().flush().ok();
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        crossterm::terminal::disable_raw_mode().ok();
        let _ = child.kill();
        let _ = child.wait();
        if let Some(h) = timer_handle { let _ = h.join(); }

        println!("\n\n═══ CAPTURE COMPLETE ═══");
        println!("[System] {} packets captured, {} stored", packet_count, stored_count);

        let interpretations = engine.interpret();
        if !interpretations.is_empty() {
            println!("\n═══ INTERPRETATION ═══");
            for (_, desc) in &interpretations {
                println!("  {}", desc);
            }
        }
    }

    println!("\n[System] Database saved at {}", db_path.display());
}

// ── Capture Mode (Parallel TShark + nmap) ────────────────────

fn run_capture(interface: &str, target: &str, duration: u64, no_save: bool, output: Option<&Path>,
               fast: bool, no_nmap: bool, no_tshark: bool, debug: bool) {
    let db_path = default_db_path(no_save, output);
    println!("═══════ CAPTURE ═══════");
    println!("[System] Database: {}", db_path.display());

    let conn = init_db(&db_path);
    let conn = Arc::new(Mutex::new(conn));

    // Phase 1: Start TShark in background
    let tshark_child = if !no_tshark {
        println!("[System] Starting TShark on {} for {}s...", interface, duration);
        let tshark_args = vec![
            "-i", interface, "-n", "-l", "-T", "ek",
            "-f", "not host 127.0.0.1",
            "-e", "frame.time_epoch", "-e", "frame.len",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "udp.srcport", "-e", "udp.dstport", "-e", "dns.qry.name",
        ];
        let child = sudo_cmd("tshark").args(&tshark_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().expect("Failed to start tshark");
        Some(child)
    } else {
        None
    };

    // Phase 2: Run nmap in parallel
    if !no_nmap {
        println!("[System] Starting nmap scan of {}...", target);
        let args = if fast {
            vec!["-sS", "--top-ports", "100", "--open", "-oX", "-", "-T4", "--min-rate", "1000", target]
        } else {
            vec!["-sV", "-O", "-sC", "--open", "-oX", "-", "-T4", target]
        };

        let output = sudo_cmd("nmap").args(&args)
            .stdin(Stdio::inherit())
            .output().expect("Failed to run nmap");

        let xml_str = String::from_utf8_lossy(&output.stdout);
        if !xml_str.is_empty() {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
            let c = conn.lock().unwrap();
            let summary = parse_nmap_xml(&xml_str, &c, now);
            c.execute(
                "INSERT INTO nmap_scans (target, scan_time, raw_xml, summary) VALUES (?1, ?2, ?3, ?4)",
                params![target, now, xml_str.to_string(), summary.clone()],
            ).expect("Failed to store scan");
            let device_count: u64 = c.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0);
            println!("[nmap] Found {} devices:\n{}", device_count, summary);
        }
    }

    // Phase 3: Process TShark output
    if let Some(mut child) = tshark_child {
        let child_pid = child.id();
        let timer_handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(duration));
            let _ = sudo_cmd("kill").args(["-INT", &child_pid.to_string()]).output();
        });

        if let Some(stdout_stream) = child.stdout.take() {
            let reader = std::io::BufReader::new(stdout_stream);
            let mut packet_count: u64 = 0;
            let mut stored_count: u64 = 0;
            let start = Instant::now();

            use std::io::BufRead;

            for line_result in reader.lines() {
                match line_result {
                    Ok(raw_line) => {
                        if raw_line.trim().is_empty() { continue; }
                        if raw_line.contains("\"index\"") && !raw_line.contains("\"_source\"") { continue; }

                        if debug {
                            eprintln!("[debug] {}", raw_line.trim());
                        }

                        if let Some((epoch, ip_src, ip_dst, tcp_src, tcp_dst, udp_src, udp_dst, dns_qry, frame_len)) = extract_fields(&raw_line) {
                            packet_count += 1;
                            let c = conn.lock().unwrap();
                            let _ = c.execute(
                                "INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json, frame_len) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                params![epoch, ip_src, ip_dst, tcp_src.map(|p| p as i32), tcp_dst.map(|p| p as i32), udp_src.map(|p| p as i32), udp_dst.map(|p| p as i32), dns_qry, raw_line.trim(), frame_len.map(|p| p as i32)]
                            );
                            stored_count += 1;

                            if packet_count.is_multiple_of(100) {
                                let elapsed = start.elapsed().as_secs();
                                print!("\r\x1b[K  {} captured, {} stored, {}s elapsed  ", packet_count, stored_count, elapsed);
                                io::stdout().flush().ok();
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            let _ = child.kill();
            let _ = child.wait();
        let _ = timer_handle.join();

            println!("\n\n═══ CAPTURE COMPLETE ═══");
            println!("[System] {} packets captured, {} stored", packet_count, stored_count);
        }
    }

    let device_count: u64 = conn.lock().unwrap().query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0);
    println!("[System] {} devices in database", device_count);
    println!("[System] Database saved at {}", db_path.display());
    println!("[System] To chat: correlator chat -d {}", db_path.display());
}

// ── Chat Mode ────────────────────────────────────────────────

fn run_chat(db_path: &Path, model: &str, live_mode: bool) {
    println!("\n═══════ NETWORK INTELLIGENCE ═══════");

    // Check Ollama first
    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        println!("[System] Ollama not available. Entering search mode.");
        println!("[System] Use / prefix for search commands: /ip, /port, /dns, /find, /devices, /stats, /help\n");
        run_search(db_path, None);
        return;
    }

    println!("[System] Building context from {}", db_path.display());
    let ctx = build_network_context(db_path);
    let context_str = format_context_for_ai(&ctx);

    // Initialize belief system from detector findings
    let beliefs = Arc::new(Mutex::new(BeliefSystem::new()));
    {
        let mut sys = beliefs.lock().unwrap();
        sys.initialize_from_findings(&ctx.findings);
        // Ensure all discovered IPs have a belief entry
        for ip in ctx.profiles.keys() {
            sys.ensure_ip(ip);
        }
    }
    let _ = BELIEFS.set(beliefs.clone());

    // Start background scanner thread
    let config = load_config();
    let scanner_beliefs = beliefs.clone();
    let (scanner_tx, scanner_rx) = std::sync::mpsc::channel::<ScannerEvent>();
    let _scanner_thread = start_scanner(scanner_beliefs, scanner_tx, config.interface.clone());

    // Add belief info to context
    let belief_context = {
        let sys = beliefs.lock().unwrap();
        let top = ctx.findings.iter().take(5).map(|f| f.ip.as_str()).collect::<Vec<_>>();
        format!("\n\n## Belief System\n\
            Each IP tracked with 5-category distribution: BOT, IOT, CAMERA, CLEAN, UNKNOWN.\n\
            Confidence is % probability. Entropy bits = uncertainty level (higher = less certain).\n\
            IPs with <90% confidence in any category are auto-scanned in background.\n\
            Top flagged IPs: {}. {} total IPs tracked.\n\
            Use get_beliefs tool to query current state.",
            top.join(", "), sys.len())
    };

    let system_prompt = if live_mode {
        "LIVE CAPTURE. Packets are arriving now. Query the DB for current data.\n\n\
         USE YOUR TOOLS. Do NOT tell the user to do things manually.\n\
         You have: sql, search, scan_ip, get_beliefs, nmap, tshark, websearch, webfetch.\n\n\
         When the user asks something, USE A TOOL. Don't explain how to do it.\n\
         Example: 'Find the OS' → use scan_ip tool immediately.\n\
         Example: 'What ports are these?' → use websearch tool immediately.\n\n\
         RULES:\n\
         - NEVER tell the user to run commands themselves\n\
         - NEVER explain how to use tools — just use them\n\
         - NEVER hallucinate example output — run the real tool\n\
         - Be brief. 1-2 sentences max."
    } else {
        "You are a network analyst with a packet database.\n\n\
         USE YOUR TOOLS. Do NOT tell the user to do things manually.\n\
         You have: sql, search, scan_ip, get_beliefs, nmap, tshark, websearch, webfetch.\n\n\
         When the user asks something, USE A TOOL. Don't explain how to do it.\n\n\
         RULES:\n\
         - NEVER tell the user to run commands themselves\n\
         - NEVER explain how to use tools — just use them\n\
         - NEVER hallucinate example output — run the real tool\n\
         - Be brief. 1-2 sentences max."
    };

    println!("\n[System] Chat ready. {} devices, {} packets, {} findings loaded.",
        ctx.devices.len(), ctx.packet_count, ctx.findings.len());
    println!("[System] Tools: nmap, tshark, sql, search, webfetch, websearch, scan_ip, get_beliefs");
    println!("[System] Belief tracker: scanning {} IPs in background (use /beliefs to see)\n",
        {
            let sys = beliefs.lock().unwrap();
            sys.len()
        });

    let conn = open_db(db_path);
    let mut messages: Vec<Value> = Vec::new();
    let mut input = String::new();

    // System message
    messages.push(json!({
        "role": "system",
        "content": system_prompt
    }));

    // First message: inject context
    messages.push(json!({
        "role": "user",
        "content": format!("Loaded {} devices, {} packets, {} findings.\n\n{}{}",
            ctx.devices.len(), ctx.packet_count, ctx.findings.len(), context_str, belief_context)
    }));
    messages.push(json!({
        "role": "assistant",
        "content": "Got it. I can see your network and I'm tracking beliefs. What do you want to know?"
    }));

    // Tool definitions for Ollama
    let tools = vec![
        json!({
            "type": "function",
            "function": {
                "name": "nmap",
                "description": "Ping-sweep a single IP to check if it is online. Does NOT detect ports or services.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "description": "IP address to ping" }
                    },
                    "required": ["target"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "tshark",
                "description": "Capture live network traffic (requires sudo). Default 10s if duration omitted.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "filter": { "type": "string", "description": "BPF capture filter" },
                        "duration": { "type": "number", "description": "Capture duration in seconds (max 60, default 10)" }
                    },
                    "required": []
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "sql",
                "description": "Query the packet database directly",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "SELECT query to run" }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "search",
                "description": "Search the database for IPs, ports, DNS, connections",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query" }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "websearch",
                "description": "Search the internet for information",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query" }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "webfetch",
                "description": "Fetch a webpage",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "description": "URL to fetch" }
                    },
                    "required": ["url"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "scan_ip",
                "description": "Run nmap ping sweep + port/version scan on a single IP. Updates belief system.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "description": "IP address to scan" }
                    },
                    "required": ["target"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "get_beliefs",
                "description": "Get current belief distribution for all tracked or a specific IP: BOT/IOT/CAM/CLEAN/UNK probabilities + entropy.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "description": "Optional IP to query (omit for all)" }
                    },
                    "required": []
                }
            }
        }),
    ];

    loop {
        // Drain scanner events before showing prompt
        loop {
            match scanner_rx.try_recv() {
                Ok(ScannerEvent::ScanStarted { ip, tool }) => {
                    println!("  [Scanner] {} scanning {}...", tool, ip);
                }
                Ok(ScannerEvent::ScanComplete { ip, result }) => {
                    let status = if result.is_alive { "up" } else { "down" };
                    let ports = if result.open_ports.is_empty() {
                        "no ports".to_string()
                    } else {
                        format!("ports: {:?}", result.open_ports)
                    };
                    let os = result.os_hint.as_deref().unwrap_or("");
                    println!("  [Scanner] {} → {} ({}, {})",
                        ip, status, ports,
                        if os.is_empty() { "no OS info" } else { os },
                    );
                    if let Ok(sys) = beliefs.lock() {
                        if let Some(line) = sys.format_ip(&ip) {
                            println!("  [↻] {}", line);
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }

        print!("you> ");
        io::stdout().flush().ok();
        input.clear();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => { eprintln!("[Error] {}", e); break; }
        }

        let question = input.trim().to_string();
        if question.is_empty() { continue; }
        if question == "quit" || question == "exit" || question == "q" { break; }

        // /commands
        if let Some(cmd) = question.strip_prefix('/') {
            match cmd {
                "beliefs" | "belief" => {
                    let sys = beliefs.lock().unwrap();
                    println!("═══ Beliefs ═══");
                    println!("{}", sys.format_all());
                }
                cmd if cmd.starts_with("scan ") => {
                    let ip = cmd[5..].trim();
                    if ip.is_empty() {
                        println!("  Usage: /scan <IP>");
                    } else {
                        println!("  [Manual] Scanning {}...", ip);
                        let is_alive = scanner::ping_sweep(ip);
                        let open_ports = if is_alive {
                            scanner::version_scan(ip)
                        } else {
                            Vec::new()
                        };
                        let os_hint = if is_alive && !open_ports.is_empty() {
                            Some(scanner::guess_os_from_ports(&open_ports))
                        } else {
                            None
                        };
                        {
                            let mut sys = beliefs.lock().unwrap();
                            sys.ensure_ip(ip);
                            sys.update_from_nmap(ip, is_alive, &open_ports);
                        }
                        println!("  [Manual] {} → {} (ports: {:?}) {}",
                            ip,
                            if is_alive { "up" } else { "down" },
                            open_ports,
                            os_hint.as_deref().unwrap_or(""),
                        );
                        if let Ok(sys) = beliefs.lock() {
                            if let Some(line) = sys.format_ip(ip) {
                                println!("  [↻] {}", line);
                            }
                        }
                    }
                }
                _ => search_execute(&conn, cmd),
            }
            continue;
        }

        // Add user message
        messages.push(json!({"role": "user", "content": question}));

        // Get AI response with tool calling
        print!("  ");
        io::stdout().flush().ok();

        let response = match ollama.chat(&messages, &tools) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("\n[Error] {}", e);
                println!("  [AI unavailable — try /help or 'quit']");
                messages.pop(); // remove failed user message
                continue;
            }
        };

        let content = response["content"].as_str().unwrap_or("").to_string();
        let tool_calls = response["tool_calls"].as_array().cloned().unwrap_or_default();

        // No tool calls — just a text response
        if tool_calls.is_empty() {
            messages.push(json!({"role": "assistant", "content": content}));
            println!();
            continue;
        }

        // Process tool calls
        messages.push(json!({"role": "assistant", "content": content, "tool_calls": tool_calls}));

        for tc in &tool_calls {
            let name = tc["function"]["name"].as_str().unwrap_or("");
            let args = tc["function"]["arguments"].clone();
            let args_str = format!("{}", args);

            let call = ToolCall {
                name: name.to_string(),
                description: args_str.clone(),
                args: tc.clone(),  // pass the whole tool call object
            };

            if ask_permission(&call) {
                let tool_result = execute_tool_call(&call, &conn, db_path);
                println!("  [Tool: {}] {}", tool_result.tool_name, tool_result.summary);

                let formatted = format!("[OK] {}: {}\n{}",
                    tool_result.tool_name, tool_result.summary, tool_result.output);
                messages.push(json!({
                    "role": "tool",
                    "content": formatted,
                }));
            } else {
                println!("  [Tool denied]");
                let denied = format!("[DENIED] User denied {}: {}", name, call.description);
                messages.push(json!({
                    "role": "tool",
                    "content": denied,
                }));
            }
        }

        // Let model respond to tool results
        print!("  ");
        io::stdout().flush().ok();
        if let Ok(follow) = ollama.chat(&messages, &tools) {
            let fc = follow["content"].as_str().unwrap_or("").to_string();
            if !fc.is_empty() {
                messages.push(json!({"role": "assistant", "content": fc}));
            }
        }
        println!();
    }

    println!("\n[System] Chat ended. {} messages recorded.", messages.len());
}

// ── Tool System ──────────────────────────────────────────────

/// A parsed tool call (before execution)
struct ToolCall {
    name: String,
    description: String,
    args: Value,
}

/// Ask user permission before executing a tool
fn ask_permission(call: &ToolCall) -> bool {
    if ALWAYS_ALLOW.load(Ordering::Relaxed) {
        return true;
    }
    // Format args nicely
    let args_str = match &call.args {
        Value::Object(map) => {
            let parts: Vec<String> = map.iter()
                .map(|(k, v)| {
                    let val = match v {
                        Value::String(s) => s.clone(),
                        other => format!("{}", other),
                    };
                    format!("{}={}", k, val)
                })
                .collect();
            parts.join(" ")
        }
        _ => format!("{}", call.args),
    };
    let display = format!("{} {}", call.name, args_str);
    let w = 58;
    let display = &display[..display.len().min(w)];
    println!();
    println!("  ┌{0:─<1$}┐", "", w + 2);
    println!("  │ {:<width$} │", display, width = w);
    println!("  ├{0:─<1$}┤", "", w + 2);
    println!("  │ {:<width$} │", "[y] Allow   [a] Always   [n] Deny", width = w);
    println!("  └{0:─<1$}┘", "", w + 2);
    print!("  > ");
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    match input.trim().to_lowercase().as_str() {
        "a" | "always" => {
            ALWAYS_ALLOW.store(true, Ordering::Relaxed);
            true
        }
        "y" | "yes" => true,
        _ => false,
    }
}

/// Execute a parsed tool call
fn execute_tool_call(call: &ToolCall, conn: &Connection, db_path: &Path) -> ToolResult {
    // Try structured tool execution first
    if let Some(result) = try_exec_tool(&call.args, conn, db_path) {
        return result;
    }

    // Fallback: try plain text parsing from description
    let parts: Vec<&str> = call.description.splitn(2, ' ').collect();
    if parts.len() == 2 {
        let cmd = parts[0].trim_matches('`');
        let args = parts[1].trim().trim_matches('"').trim_matches('\'');
        match cmd {
            "nmap" => return run_tool_nmap(args),
            "tshark" => return run_tool_tshark(args, 10, db_path),
            "sql" => return run_tool_sql(args, conn),
            "search" => return run_tool_search(args, conn),
            "websearch" => return run_tool_websearch(args),
            "webfetch" => return run_tool_webfetch(args),
            _ => {}
        }
    }

    ToolResult { tool_name: call.name.clone(), summary: "Unknown tool".into(), output: "Failed to parse tool arguments".into() }
}

struct ToolResult {
    tool_name: String,
    summary: String,
    output: String,
}

/// Try to execute a tool from parsed JSON
fn try_exec_tool(val: &Value, conn: &Connection, db_path: &Path) -> Option<ToolResult> {
    // Handle Ollama tool calling format: {"function": {"name": "...", "arguments": {...}}}
    if let Some(func) = val.get("function") {
        let tool = func.get("name").and_then(|t| t.as_str())?;
        let args = func.get("arguments").cloned().unwrap_or(json!({}));
        return try_exec_tool_named(tool, &args, conn, db_path);
    }
    // Handle legacy format: {"tool": "...", ...}
    let tool = val.get("tool").and_then(|t| t.as_str())?;
    try_exec_tool_named(tool, val, conn, db_path)
}

fn try_exec_tool_named(tool: &str, val: &Value, conn: &Connection, db_path: &Path) -> Option<ToolResult> {
    match tool {
        "nmap" => {
            let target = val.get("target").and_then(|t| t.as_str()).unwrap_or("");
            if !is_valid_target(target) {
                return Some(ToolResult {
                    tool_name: "nmap".into(),
                    summary: "Invalid target".into(),
                    output: format!("Rejected: '{}' is not a valid IP/CIDR", target),
                });
            }
            Some(run_tool_nmap(target))
        }
        "tshark" => {
            let filter = val.get("filter").and_then(|t| t.as_str()).unwrap_or("");
            if !is_valid_bpf(filter) {
                return Some(ToolResult {
                    tool_name: "tshark".into(),
                    summary: "Invalid filter".into(),
                    output: format!("Rejected: '{}' contains invalid characters", filter),
                });
            }
            let duration = val.get("duration").and_then(|d| d.as_u64()).unwrap_or(10).min(60);
            Some(run_tool_tshark(filter, duration, db_path))
        }
        "sql" => {
            let query = val.get("query").and_then(|q| q.as_str()).unwrap_or("");
            if !is_safe_sql(query) {
                return Some(ToolResult {
                    tool_name: "sql".into(),
                    summary: "Rejected unsafe SQL".into(),
                    output: "Only SELECT queries are allowed.".into(),
                });
            }
            Some(run_tool_sql(query, conn))
        }
        "search" => {
            let query = val.get("query").and_then(|q| q.as_str()).unwrap_or("");
            if !is_safe_search(query) {
                return Some(ToolResult {
                    tool_name: "search".into(),
                    summary: "Invalid search".into(),
                    output: "Search contains invalid characters.".into(),
                });
            }
            Some(run_tool_search(query, conn))
        }
        "webfetch" => {
            let url = val.get("url").and_then(|u| u.as_str()).unwrap_or("");
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Some(ToolResult {
                    tool_name: "webfetch".into(),
                    summary: "Invalid URL".into(),
                    output: "URL must start with http:// or https://".into(),
                });
            }
            Some(run_tool_webfetch(url))
        }
        "websearch" => {
            let query = val.get("query").and_then(|q| q.as_str()).unwrap_or("");
            if query.is_empty() || query.len() > 200 {
                return Some(ToolResult {
                    tool_name: "websearch".into(),
                    summary: "Invalid query".into(),
                    output: "Query must be 1-200 characters.".into(),
                });
            }
            Some(run_tool_websearch(query))
        }
        "scan_ip" => {
            let target = val.get("target").and_then(|t| t.as_str()).unwrap_or("");
            if !is_valid_target(target) {
                return Some(ToolResult {
                    tool_name: "scan_ip".into(),
                    summary: "Invalid target".into(),
                    output: format!("Rejected: '{}' is not a valid IP address", target),
                });
            }
            Some(run_tool_scan_ip(target))
        }
        "get_beliefs" => {
            let target = val.get("target").and_then(|t| t.as_str()).unwrap_or("");
            let result = run_tool_get_beliefs(if target.is_empty() { None } else { Some(target) });
            Some(result)
        }
        _ => None,
    }
}

/// Try to parse and execute a tool from a text snippet
fn try_parse_tool_text(text: &str, conn: &Connection, db_path: &Path) -> Option<ToolResult> {
    let trimmed = text.trim();

    // Try JSON first
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        if val.get("tool").is_some() {
            return try_exec_tool(&val, conn, db_path);
        }
    }

    // Try simple tool commands: "toolname args"
    // Must be short, on one line, no semicolons/pipes
    if trimmed.len() > 200 { return None; }
    if trimmed.contains(';') || trimmed.contains('|') || trimmed.contains('`') { return None; }

    let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
    if parts.len() != 2 { return None; }

    let cmd = parts[0].trim_matches('`');
    let args = parts[1].trim().trim_matches('"').trim_matches('\'');

    match cmd {
        "nmap" if is_valid_target(args) => return Some(run_tool_nmap(args)),
        "tshark" if is_valid_bpf(args) => return Some(run_tool_tshark(args, 10, db_path)),
        "sql" if is_safe_sql(args) => return Some(run_tool_sql(args, conn)),
        "search" if is_safe_search(args) => return Some(run_tool_search(args, conn)),
        "webfetch" if args.starts_with("http") && !args.contains(';') && !args.contains('|') => {
            return Some(run_tool_webfetch(args));
        }
        "websearch" if !args.is_empty() && args.len() <= 200 && !args.contains(';') && !args.contains('|') => {
            return Some(run_tool_websearch(args));
        }
        _ => {}
    }

    None
}

// ── Input Validation ─────────────────────────────────────────

fn is_valid_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 64 { return false; }
    // Reject CIDR notation (subnets) — only allow single IPs
    if target.contains('/') { return false; }
    // Only allow: digits, dots, commas, hyphens, spaces (for ranges)
    target.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ',' || c == '-' || c == ' ')
}

fn is_valid_bpf(filter: &str) -> bool {
    if filter.is_empty() { return true; } // empty = capture all
    if filter.len() > 256 { return false; }
    // Reject shell metacharacters
    let dangerous = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '"', '\''];
    !filter.chars().any(|c| dangerous.contains(&c))
}

fn is_safe_sql(query: &str) -> bool {
    let upper = query.trim().to_uppercase();
    // Only allow SELECT, WITH, SHOW, EXPLAIN
    upper.starts_with("SELECT") || upper.starts_with("WITH") ||
    upper.starts_with("SHOW") || upper.starts_with("EXPLAIN")
}

fn is_safe_search(query: &str) -> bool {
    if query.is_empty() || query.len() > 128 { return false; }
    let dangerous = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r'];
    !query.chars().any(|c| dangerous.contains(&c))
}

fn run_tool_nmap(target: &str) -> ToolResult {
    println!("\n  [Tool] Running nmap on {}...", target);
    let args = vec!["-sn", "-T5", "--max-retries", "1", "--host-timeout", "5s", target];
    let output = sudo_cmd("nmap").args(&args)
        .output().expect("Failed to run nmap");
    let xml = String::from_utf8_lossy(&output.stdout);

    let conn = Connection::open(":memory:").unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    let summary = parse_nmap_xml(&xml, &conn, now);

    let device_count: u64 = conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0);

    ToolResult {
        tool_name: "nmap".into(),
        summary: format!("Found {} devices on {}", device_count, target),
        output: summary,
    }
}

fn run_tool_tshark(filter: &str, duration: u64, _db_path: &Path) -> ToolResult {
    let iface = load_config().interface;
    println!("\n  [Tool] Capturing traffic for {}s (interface: {}, filter: {})...", duration, iface, filter);
    let mut args = vec!["-i", &iface, "-n", "-l", "-T", "ek", "-f", "not host 127.0.0.1"];
    if !filter.is_empty() {
        args = vec!["-i", &iface, "-n", "-l", "-T", "ek", "-f", filter];
    }
    args.extend(["-e", "frame.time_epoch", "-e", "frame.len",
                 "-e", "ip.src", "-e", "ip.dst",
                 "-e", "tcp.srcport", "-e", "tcp.dstport",
                 "-e", "udp.srcport", "-e", "udp.dstport", "-e", "dns.qry.name"]);

    let mut child = sudo_cmd("tshark").args(&args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().expect("Failed to start tshark");

    let child_pid = child.id();
    let timer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(duration));
        let _ = sudo_cmd("kill").args(["-INT", &child_pid.to_string()]).output();
    });

    let mut packets = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let reader = std::io::BufReader::new(stdout);
        use std::io::BufRead;
        for line in reader.lines().map_while(|r| r.ok()) {
            if let Some((_, src, dst, _, _, _, _, dns, _)) = extract_fields(&line) {
                let _src = src.unwrap_or_default();
                let dst = dst.unwrap_or_default();
                let dns = dns.map(|d| format!(" [{}]", d)).unwrap_or_default();
                packets.push(format!("→ {}{}", dst, dns));
            }
            if packets.len() >= 50 { break; }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = timer.join();

    ToolResult {
        tool_name: "tshark".into(),
        summary: format!("Captured {} packets ({}s)", packets.len(), duration),
        output: packets.join("\n"),
    }
}

fn run_tool_sql(query: &str, conn: &Connection) -> ToolResult {
    println!("\n  [Tool] Running SQL: {}", query);

    // Additional safety: block multiple statements (more than one semicolon)
    let semicolon_count = query.chars().filter(|&c| c == ';').count();
    if semicolon_count > 1 {
        return ToolResult {
            tool_name: "sql".into(),
            summary: "Rejected multi-statement query".into(),
            output: "Only single SELECT queries are allowed.".into(),
        };
    }

    // Block dangerous keywords even in SELECT
    let upper = query.to_uppercase();
    let blocked = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE", "EXEC", "EXECUTE", "UNION", "INTO", "LOAD", "INFILE", "OUTFILE"];
    for kw in blocked {
        if upper.contains(kw) {
            return ToolResult {
                tool_name: "sql".into(),
                summary: "Rejected query with blocked keyword".into(),
                output: format!("Keyword '{}' is not allowed.", kw),
            };
        }
    }

    match conn.prepare(query) {
        Ok(mut stmt) => {
            let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let mut rows = stmt.query([]).unwrap();
            let mut output = vec![cols.join(" | ")];
            let mut count = 0;
            while let Some(row) = rows.next().unwrap() {
                let vals: Vec<String> = (0..cols.len()).map(|i| {
                    row.get::<_, String>(i).unwrap_or_else(|_| "NULL".into())
                }).collect();
                output.push(vals.join(" | "));
                count += 1;
                if count >= 20 { break; }
            }
            ToolResult {
                tool_name: "sql".into(),
                summary: format!("{} rows returned", count),
                output: output.join("\n"),
            }
        }
        Err(e) => ToolResult {
            tool_name: "sql".into(),
            summary: "SQL error".into(),
            output: format!("Error: {}", e),
        },
    }
}

fn run_tool_search(query: &str, conn: &Connection) -> ToolResult {
    println!("\n  [Tool] Searching: {}", query);
    let mut output = Vec::new();
    // Capture search output by executing the search
    let parts: Vec<&str> = query.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let arg = parts.get(1).unwrap_or(&"");

    match cmd.as_str() {
        "ip" => {
            let pattern = format!("%{}%", arg);
            let mut stmt = conn.prepare(
                "SELECT epoch, ip_src, ip_dst, tcp_dst_port, dns_query FROM packets WHERE ip_src LIKE ?1 OR ip_dst LIKE ?1 ORDER BY epoch DESC LIMIT 20"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            }).unwrap();
            for row in rows {
                let (_epoch, src, dst, port, dns): (Option<f64>, Option<String>, Option<String>, Option<i32>, Option<String>) = row.unwrap();
                output.push(format!("{} → {} port:{} dns:{}", src.unwrap_or_default(), dst.unwrap_or_default(), port.unwrap_or(0), dns.unwrap_or_default()));
            }
        }
        "devices" => {
            let mut stmt = conn.prepare("SELECT ip, os_guess, ports FROM devices").unwrap();
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            for row in rows {
                let (ip, os, ports): (String, Option<String>, String) = row.unwrap();
                output.push(format!("{} [{}] {}", ip, os.unwrap_or_default(), ports));
            }
        }
        "connections" => {
            let pattern = format!("%{}%", arg);
            let mut stmt = conn.prepare(
                "SELECT ip_dst, COUNT(*) as cnt FROM packets WHERE ip_src LIKE ?1 GROUP BY ip_dst ORDER BY cnt DESC LIMIT 10"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            for row in rows {
                let (ip, count): (String, u64) = row.unwrap();
                output.push(format!("→ {} (×{})", ip, count));
            }
        }
        _ => {
            output.push(format!("Unknown search command: {}", cmd));
        }
    }

    ToolResult {
        tool_name: "search".into(),
        summary: format!("Search '{}' returned {} results", query, output.len()),
        output: output.join("\n"),
    }
}

fn run_tool_webfetch(url: &str) -> ToolResult {
    println!("\n  [Tool] Fetching {}...", url);
    match reqwest::blocking::get(url) {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            // Truncate to ~4000 chars for LLM context
            let truncated = if text.len() > 4000 { &text[..4000] } else { &text };
            ToolResult {
                tool_name: "webfetch".into(),
                summary: format!("Fetched {} (status: {}, {} bytes)", url, status, text.len()),
                output: truncated.to_string(),
            }
        }
        Err(e) => ToolResult {
            tool_name: "webfetch".into(),
            summary: "Fetch failed".into(),
            output: format!("Error: {}", e),
        },
    }
}

fn run_tool_websearch(query: &str) -> ToolResult {
    println!("\n  [Tool] Searching web: {}...", query);
    // Use DuckDuckGo lite for simple web search
    let search_url = format!("https://lite.duckduckgo.com/lite/?q={}", urlencoding::encode(query));
    match reqwest::blocking::get(&search_url) {
        Ok(resp) => {
            let html = resp.text().unwrap_or_default();
            // Extract text content from the simple HTML
            let results = extract_search_results(&html);
            if results.is_empty() {
                ToolResult {
                    tool_name: "websearch".into(),
                    summary: format!("No results for '{}'", query),
                    output: "No search results found. Try different keywords.".into(),
                }
            } else {
                ToolResult {
                    tool_name: "websearch".into(),
                    summary: format!("Found {} results for '{}'", results.len(), query),
                    output: results.join("\n\n"),
                }
            }
        }
        Err(e) => ToolResult {
            tool_name: "websearch".into(),
            summary: "Search failed".into(),
            output: format!("Error: {}", e),
        },
    }
}

fn run_tool_scan_ip(target: &str) -> ToolResult {
    println!("\n  [Tool] Scanning {} (ports + OS)...", target);
    let is_alive = scanner::ping_sweep(target);
    let open_ports = if is_alive { scanner::version_scan(target) } else { Vec::new() };
    let os_real = if is_alive { scanner::os_scan(target) } else { None };
    let os_hint = if let Some(ref os) = os_real {
        os.clone()
    } else if is_alive && !open_ports.is_empty() {
        scanner::guess_os_from_ports(&open_ports)
    } else {
        "unknown".to_string()
    };
    if let Some(beliefs) = BELIEFS.get() {
        let mut sys = beliefs.lock().unwrap();
        sys.ensure_ip(target);
        sys.update_from_nmap(target, is_alive, &open_ports);
    }
    let status = if is_alive { "up" } else { "down" };
    let ports_str = if open_ports.is_empty() {
        "no open ports".to_string()
    } else {
        format!("{} open ports: {:?}", open_ports.len(), open_ports)
    };
    ToolResult {
        tool_name: "scan_ip".into(),
        summary: format!("{} → {} ({})", target, status, os_hint),
        output: format!("IP: {}\nStatus: {}\nOS: {}\n{}",
            target, status, os_hint, ports_str),
    }
}

fn run_tool_get_beliefs(target: Option<&str>) -> ToolResult {
    if let Some(beliefs) = BELIEFS.get() {
        let sys = beliefs.lock().unwrap();
        if let Some(ip) = target {
            if let Some(line) = sys.format_ip(ip) {
                ToolResult {
                    tool_name: "get_beliefs".into(),
                    summary: format!("Beliefs for {}", ip),
                    output: line,
                }
            } else {
                ToolResult {
                    tool_name: "get_beliefs".into(),
                    summary: format!("IP {} not tracked", ip),
                    output: format!("IP {} has no belief data. Use scan_ip to start tracking.", ip),
                }
            }
        } else {
            let output = sys.format_all();
            ToolResult {
                tool_name: "get_beliefs".into(),
                summary: format!("Beliefs for {} IPs", sys.len()),
                output,
            }
        }
    } else {
        ToolResult {
            tool_name: "get_beliefs".into(),
            summary: "Belief system not initialized".into(),
            output: "Belief system is not available. Run in chat mode.".into(),
        }
    }
}

fn sudo_cmd(prog: &str) -> Command {
    let is_root = std::process::Command::new("id").arg("-u").output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if is_root {
        Command::new(prog)
    } else {
        let mut c = Command::new("sudo");
        c.arg(prog);
        c
    }
}

fn extract_search_results(html: &str) -> Vec<String> {
    let mut results = Vec::new();
    // Simple extraction: find <a> tags with href and text
    let mut in_result = false;
    let mut current_title = String::new();
    let mut current_url = String::new();
    let mut current_snippet = String::new();

    for line in html.lines() {
        let trimmed = line.trim();
        // Look for result links
        if trimmed.contains("result__a") || trimmed.contains("result-link") {
            if let Some(href_start) = trimmed.find("href=\"") {
                let rest = &trimmed[href_start + 6..];
                if let Some(href_end) = rest.find('"') {
                    current_url = rest[..href_end].to_string();
                    in_result = true;
                }
            }
            // Extract title text
            if let Some(text_start) = trimmed.find('>') {
                let text = &trimmed[text_start + 1..];
                if let Some(text_end) = text.find('<') {
                    current_title = text[..text_end].trim().to_string();
                }
            }
        }
        // Look for snippet
        if in_result && (trimmed.contains("result__snippet") || trimmed.contains("result-snippet")) {
            if let Some(text_start) = trimmed.find('>') {
                let text = &trimmed[text_start + 1..];
                if let Some(text_end) = text.find('<') {
                    current_snippet = text[..text_end].trim().to_string();
                }
            }
        }
        // End of result
        if in_result && !current_title.is_empty() && (!current_snippet.is_empty() || trimmed.contains("</td>")) {
            if !current_url.is_empty() || !current_title.is_empty() {
                results.push(format!("{} {}\n{}", current_title, current_url, current_snippet));
            }
            current_title = String::new();
            current_url = String::new();
            current_snippet = String::new();
            in_result = false;
            if results.len() >= 5 { break; }
        }
    }

    // Catch last result
    if in_result && !current_title.is_empty() {
        results.push(format!("{} {}\n{}", current_title, current_url, current_snippet));
    }

    // Fallback: if no structured results, grab any text content
    if results.is_empty() {
        let cleaned = html.replace("<script>", "").replace("</script>", "")
            .replace("<style>", "").replace("</style>", "");
        let text_only = cleaned
            .split(['<', '>'])
            .map(|s| s.trim())
            .filter(|s| s.len() > 20 && !s.starts_with("http"))
            .take(5)
            .collect::<Vec<_>>();
        if !text_only.is_empty() {
            results.push(text_only.join("\n"));
        }
    }

    results
}

// ── Context Builders ─────────────────────────────────────────

struct NetworkContext {
    devices: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, String)>,
    findings: Vec<correlate::Finding>,
    profiles: std::collections::HashMap<String, correlate::IpProfile>,
    cross_ref: String,
    packet_count: usize,
}

fn build_network_context(db_path: &Path) -> NetworkContext {
    let conn = init_db(db_path);
    let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    eprint!("[System] Loading {} packets...", total);
    let packets = load_from_db(&conn);

    let devices: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, String)> = {
        let mut stmt = conn.prepare(
            "SELECT ip, mac, hostname, vendor, os_guess, ports FROM devices"
        ).unwrap_or_else(|_| conn.prepare("SELECT ip, NULL, NULL, NULL, NULL, '' FROM devices").unwrap());
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap().filter_map(|r| r.ok()).collect()
    };

    drop(conn);

    let mut correlator = Correlator::new();
    correlator.ingest_batch(packets);
    let findings = correlator.correlate_with_devices(&devices);
    let cross_ref = correlator.cross_reference(&devices);

    eprintln!(" done ({} IPs, {} findings)", correlator.profiles().len(), findings.len());

    NetworkContext {
        devices,
        findings,
        profiles: correlator.profiles().clone(),
        cross_ref,
        packet_count: total as usize,
    }
}

fn format_context_for_ai(ctx: &NetworkContext) -> String {
    let mut parts = Vec::new();

    parts.push("## Flag Definitions (all 18 types detected by the correlation engine)\n\
        [BROWSER] = Web browser: HTTPS+DNS to many domains, ephemeral ports, browser CDNs\n\
        [BOT] = Confirmed botnet: precision beacon interval (CV<0.1), autocorrelation, monotonic port, minimal DNS\n\
        [SERVER] = Server: many unique clients, privileged ports, inbound > outbound, long sessions\n\
        [IOT] = IoT device: UPnP/mDNS/multicast ports, few external IPs, low pps, heartbeat, UDP-dominant\n\
        [DNS_PROFILER] = DNS profiler: high qps (>8), many unique domains (>60), probes without connecting, single-label (DGA) queries\n\
        [BEACON] = Periodic beacon: tight interval (CV<0.05) or jittered (CV 0.05-0.25), single destination, low-payload keep-alive\n\
        [SCANNER] = Scanner: many unique ports (>20), network sweep (>15 hosts, <2 pkts/host), SYN scan pattern, sequential ports\n\
        [STREAMING] = Streaming media: sustained high volume, UDP-dominant, streaming CDN domains, high pps\n\
        [CLOUD_SYNC] = Cloud sync: repeated DNS to cloud domains, steady bidirectional traffic\n\
        [VPN] = VPN tunnel: VPN ports (1194/4500/500/1723/8443), single destination tunnel, uniform encrypted packet sizes\n\
        [TOR] = Tor: Tor ports (9001/9030/9150), relay behavior (many source IPs), long-lived circuits\n\
        [GAME] = Game client: game ports, bursty pattern, 10-200 pps, UDP-dominant\n\
        [LATERAL_MOVEMENT] = Lateral movement: connects to 4+ internal hosts, management ports, rapid scanning\n\
        [DATA_EXFIL] = Data exfiltration: high outbound ratio (>8:1), single external IP concentration, minimal DNS, sustained\n\
        [C2_BEACON] = C2 beacon: regular/jittered beacon to single external IP, minimal DNS, small payloads, recon-scale volume\n\
        [NET_RECON] = Network recon: probes management ports (22/23/80/443/3389/5900/2323/9100), light touch (<5 pkts/host), unanswered probes, no DNS\n\
        [PRINTER_IOT] = Printer/IoT: printer ports (9100/631), IoT signal ports, very low rate (<2 pps), vendor keywords match, UDP-dominant\n\
        [UNKNOWN] = No detector matched (report basic packet/DNS stats)\n\n\
        Confidence: each detector starts at 0.0 and adds 0.1-0.5 per signal that triggers; emitted if >= 0.35, capped at 1.0.\n\
        Detail: semicolon-separated list of indicators that contributed to the finding.".to_string());

    if !ctx.devices.is_empty() {
        parts.push(format!("## Known Devices ({})\n{}", ctx.devices.len(),
            ctx.devices.iter().map(|(ip, mac, hostname, _vendor, _os, ports)| {
                format!("{} | {} | {} | Ports: {}",
                    ip,
                    mac.as_deref().unwrap_or("?"),
                    hostname.as_deref().unwrap_or("unknown"),
                    if ports.is_empty() { "none" } else { ports })
            }).collect::<Vec<_>>().join("\n")));
    }

    let total_dns: usize = ctx.profiles.values().map(|p| p.dns_domains.len()).sum();
    parts.push(format!("## Stats\n{} packets, {} IPs, {} DNS, {} findings",
        ctx.packet_count, ctx.profiles.len(), total_dns, ctx.findings.len()));

    let mut profiles: Vec<_> = ctx.profiles.values().collect();
    profiles.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    if !profiles.is_empty() {
        parts.push(format!("## Top Talkers\n{}",
            profiles.iter().take(10).map(|p| {
                let dns = if p.dns_domains.is_empty() { String::new() } else { format!(", dns:{}", p.dns_domains.keys().take(3).cloned().collect::<Vec<_>>().join(",")) };
                format!("{}: {} pkts (↑{} ↓{}){}", p.ip, p.packet_count, p.outbound_count, p.inbound_count, dns)
            }).collect::<Vec<_>>().join("\n")));
    }

    if !ctx.findings.is_empty() {
        parts.push(format!("## Findings\n{}",
            ctx.findings.iter().take(10).map(|f|
                format!("{} [{}] {}: {}", f.ip, f.kind, (f.confidence * 100.0) as u32, f.detail)
            ).collect::<Vec<_>>().join("\n")));
    }

    parts.join("\n\n")
}

// ── Nmap XML Parser ──────────────────────────────────────────

fn parse_nmap_xml(xml: &str, conn: &Connection, scan_time: f64) -> String {
    let mut summary_lines = Vec::new();
    let mut current_ip: Option<String> = None;
    let mut current_mac: Option<String> = None;
    let mut current_hostname: Option<String> = None;
    let mut current_os: Option<String> = None;
    let mut current_vendor: Option<String> = None;
    let mut current_state: Option<String> = None;
    let mut ports: Vec<String> = Vec::new();
    let mut in_host = false;
    let mut in_ports = false;

    for line in xml.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("<host ") {
            if in_host {
                if let Some(ip) = &current_ip {
                    let ports_str = ports.join(", ");
                    upsert_device(conn, ip, current_mac.as_deref(), current_hostname.as_deref(),
                                  current_vendor.as_deref(), current_os.as_deref(), &ports_str, scan_time);
                    summary_lines.push(format!("{} ({}) — {} [{}]", ip,
                        current_hostname.as_deref().unwrap_or("unknown"),
                        current_os.as_deref().unwrap_or("OS unknown"),
                        if ports_str.is_empty() { "no open ports".into() } else { ports_str }));
                }
            }
            in_host = true;
            current_ip = None;
            current_mac = None;
            current_hostname = None;
            current_os = None;
            current_vendor = None;
            current_state = None;
            ports.clear();
            in_ports = false;
        }

        if !in_host { continue; }

        if trimmed.starts_with("<status ") {
            if let Some(start) = trimmed.find("state=\"") {
                let rest = &trimmed[start + 7..];
                if let Some(end) = rest.find('"') {
                    current_state = Some(rest[..end].to_string());
                }
            }
        }

        if trimmed.starts_with("<address ") {
            let mut addr_val = None;
            let mut addr_type = None;
            let mut vendor_val = None;
            if let Some(start) = trimmed.find("addr=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') { addr_val = Some(rest[..end].to_string()); }
            }
            if let Some(start) = trimmed.find("addrtype=\"") {
                let rest = &trimmed[start + 10..];
                if let Some(end) = rest.find('"') { addr_type = Some(rest[..end].to_string()); }
            }
            if let Some(start) = trimmed.find("vendor=\"") {
                let rest = &trimmed[start + 8..];
                if let Some(end) = rest.find('"') { vendor_val = Some(rest[..end].to_string()); }
            }
            if let (Some(addr), Some(typ)) = (addr_val, addr_type) {
                if typ == "ipv4" { current_ip = Some(addr); }
                else if typ == "mac" { current_mac = Some(addr); current_vendor = vendor_val; }
            }
        }

        if trimmed.starts_with("<hostname ") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') { current_hostname = Some(rest[..end].to_string()); }
            }
        }

        if trimmed.starts_with("<ports>") { in_ports = true; }
        if trimmed.starts_with("</ports>") { in_ports = false; }

        if in_ports && trimmed.starts_with("<port ") {
            let port_num = if let Some(start) = trimmed.find("portid=\"") {
                let rest = &trimmed[start + 8..];
                if let Some(end) = rest.find('"') { &rest[..end] } else { "?" }
            } else { "?" };
            let mut state = "unknown";
            if let Some(start) = trimmed.find("state=\"") {
                let rest = &trimmed[start + 7..];
                if let Some(end) = rest.find('"') { state = &rest[..end]; }
            }
            ports.push(format!("{}/{} ?", port_num, state));
        }

        if in_ports && trimmed.starts_with("<state ") {
            if let Some(start) = trimmed.find("state=\"") {
                let rest = &trimmed[start + 7..];
                if let Some(end) = rest.find('"') {
                    let state_val = &rest[..end];
                    if let Some(last) = ports.last_mut() {
                        *last = last.replacen("unknown", state_val, 1);
                    }
                }
            }
        }

        if in_ports && trimmed.starts_with("<service ") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    let svc = &rest[..end];
                    if let Some(last) = ports.last_mut() {
                        *last = last.replace("?", svc);
                    }
                }
            }
        }

        if trimmed.starts_with("<osmatch ") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    if current_os.is_none() { current_os = Some(rest[..end].to_string()); }
                }
            }
        }

        if trimmed.starts_with("</host>") {
            if let Some(ip) = &current_ip {
                if current_state.as_deref() == Some("up") || current_state.is_none() {
                    let ports_str = ports.join(", ");
                    upsert_device(conn, ip, current_mac.as_deref(), current_hostname.as_deref(),
                                  current_vendor.as_deref(), current_os.as_deref(), &ports_str, scan_time);
                    summary_lines.push(format!("{} ({}) — {} [{}]", ip,
                        current_hostname.as_deref().unwrap_or("unknown"),
                        current_os.as_deref().unwrap_or("OS unknown"),
                        if ports_str.is_empty() { "no open ports".into() } else { ports_str }));
                }
            }
            in_host = false;
        }
    }

    if in_host {
        if let Some(ip) = &current_ip {
            if current_state.as_deref() == Some("up") || current_state.is_none() {
                let ports_str = ports.join(", ");
                upsert_device(conn, ip, current_mac.as_deref(), current_hostname.as_deref(),
                              current_vendor.as_deref(), current_os.as_deref(), &ports_str, scan_time);
                summary_lines.push(format!("{} ({}) — {} [{}]", ip,
                    current_hostname.as_deref().unwrap_or("unknown"),
                    current_os.as_deref().unwrap_or("OS unknown"),
                    if ports_str.is_empty() { "no open ports".into() } else { ports_str }));
            }
        }
    }

    summary_lines.join("\n")
}

fn upsert_device(conn: &Connection, ip: &str, mac: Option<&str>, hostname: Option<&str>,
                  vendor: Option<&str>, os_guess: Option<&str>, ports: &str, scan_time: f64) {
    conn.execute(
        "INSERT INTO devices (ip, mac, hostname, vendor, os_guess, ports, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT(ip) DO UPDATE SET
            mac = COALESCE(excluded.mac, mac),
            hostname = COALESCE(excluded.hostname, hostname),
            vendor = COALESCE(excluded.vendor, vendor),
            os_guess = COALESCE(excluded.os_guess, os_guess),
            ports = CASE WHEN excluded.ports != '' THEN excluded.ports ELSE ports END,
            last_seen = excluded.last_seen",
        params![ip, mac, hostname, vendor, os_guess, ports, scan_time],
    ).ok();
}

// ── Utility Commands ─────────────────────────────────────────

fn run_query(db_path: &Path, sql: &str, format: &str) {
    let conn = open_db(db_path);
    let mut stmt = conn.prepare(sql).expect("Invalid SQL");
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

    if format == "csv" {
        println!("{}", cols.join(","));
    } else {
        println!("{:?}", cols);
        println!("{}", "-".repeat(60));
    }

    let mut rows = stmt.query([]).expect("Query failed");
    let mut count = 0;
    while let Some(row) = rows.next().unwrap() {
        let values: Vec<String> = (0..cols.len()).map(|i| {
            row.get::<_, String>(i).unwrap_or_else(|_| "NULL".into())
        }).collect();

        if format == "csv" {
            println!("{}", values.join(","));
        } else {
            println!("{:?}", values);
        }
        count += 1;
    }
    println!("\n{} rows", count);
}

fn run_stats(db_path: &Path) {
    let conn = open_db(db_path);
    let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    let devices: u64 = conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0);
    let dns: u64 = conn.query_row("SELECT COUNT(DISTINCT dns_query) FROM packets WHERE dns_query IS NOT NULL", [], |r| r.get(0)).unwrap_or(0);
    let scans: u64 = conn.query_row("SELECT COUNT(*) FROM nmap_scans", [], |r| r.get(0)).unwrap_or(0);

    println!("═══ DATABASE STATS ═══");
    println!("  Packets: {}", total);
    println!("  Devices: {}", devices);
    println!("  DNS domains: {}", dns);
    println!("  Nmap scans: {}", scans);
}

fn run_dns(db_path: &Path) {
    let conn = open_db(db_path);
    let mut stmt = conn.prepare(
        "SELECT DISTINCT dns_query, ip_src, COUNT(*) as cnt FROM packets WHERE dns_query IS NOT NULL GROUP BY dns_query ORDER BY cnt DESC"
    ).unwrap();
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();

    println!("═══ DNS QUERIES ═══");
    for row in rows {
        let (query, src, count): (String, Option<String>, u64) = row.unwrap();
        println!("  {} → {} (×{})", src.unwrap_or_default(), query, count);
    }
}

fn run_top_talkers(db_path: &Path, limit: usize) {
    let conn = open_db(db_path);
    let mut stmt = conn.prepare(
        "SELECT ip_src, COUNT(*) as cnt FROM packets GROUP BY ip_src ORDER BY cnt DESC LIMIT ?1"
    ).unwrap();
    let rows = stmt.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();

    println!("═══ TOP TALKERS ═══");
    for row in rows {
        let (ip, count): (String, u64) = row.unwrap();
        println!("  {}: {} packets", ip, count);
    }
}

fn run_devices(db_path: &Path) {
    let conn = open_db(db_path);
    let mut stmt = conn.prepare(
        "SELECT ip, mac, hostname, vendor, os_guess, ports FROM devices ORDER BY ip"
    ).unwrap();
    let rows = stmt.query_map([], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
    }).unwrap();

    println!("═══ KNOWN DEVICES ═══");
    for row in rows {
        let (ip, _mac, hostname, _vendor, os_guess, ports): (String, Option<String>, Option<String>, Option<String>, Option<String>, String) = row.unwrap();
        println!("  {} ({}) — {} [{}]",
            ip,
            hostname.unwrap_or_default(),
            os_guess.unwrap_or_default(),
            if ports.is_empty() { "no ports".into() } else { ports });
    }
}

fn run_list() {
    let dir = dirs();
    if !dir.exists() {
        println!("[System] No captures yet ({} doesn't exist)", dir.display());
        return;
    }

    println!("═══ SAVED CAPTURES ═══");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "db").unwrap_or(false))
        .collect();
    entries.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

    for entry in entries.iter().take(20) {
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        println!("  {} ({:.1} MB)", entry.file_name().to_string_lossy(), size as f64 / 1_048_576.0);
    }
}

// ── Search Engine Mode ───────────────────────────────────────

fn run_search(db_path: &Path, initial_query: Option<&str>) {
    let conn = open_db(db_path);
    println!("\n═══════ NETWORK SEARCH ENGINE ═══════");
    println!("[System] Database: {}", db_path.display());
    println!("[System] Commands: ip <addr>, port <num>, dns <domain>, find <text>, devices, stats, help, quit\n");

    // If initial query provided, run it and exit
    if let Some(q) = initial_query {
        search_execute(&conn, q);
        return;
    }

    let mut input = String::new();
    loop {
        print!("search> ");
        io::stdout().flush().ok();
        input.clear();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => { eprintln!("[Error] {}", e); break; }
        }

        let query = input.trim().to_string();
        if query.is_empty() { continue; }
        if query == "quit" || query == "exit" || query == "q" { break; }

        search_execute(&conn, &query);
    }

    println!("\n[System] Search ended.");
}

fn search_execute(conn: &Connection, query: &str) {
    let parts: Vec<&str> = query.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let arg = parts.get(1).unwrap_or(&"");

    match cmd.as_str() {
        "help" | "h" | "?" => {
            println!("Commands:");
            println!("  ip <addr>       — find all traffic to/from an IP");
            println!("  port <num>      — find all traffic on a port");
            println!("  dns <domain>    — find DNS queries matching domain");
            println!("  find <text>     — search all fields for text");
            println!("  devices         — list all known devices");
            println!("  stats           — show capture statistics");
            println!("  talkers [n]     — top n talkers (default 20)");
            println!("  recent [n]      — last n packets (default 20)");
            println!("  connections <ip> — show who this IP talks to");
            println!("  services <ip>   — show services on this IP");
        }
        "ip" | "host" => {
            if arg.is_empty() { println!("Usage: ip <address>"); return; }
            let pattern = format!("%{}%", arg);
            let mut stmt = conn.prepare(
                "SELECT epoch, ip_src, ip_dst, tcp_dst_port, udp_dst_port, dns_query FROM packets WHERE ip_src LIKE ?1 OR ip_dst LIKE ?1 ORDER BY epoch DESC LIMIT 100"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            }).unwrap();
            println!("Traffic for {}:", arg);
            for row in rows {
                let (epoch, src, dst, tcp_port, udp_port, dns): (Option<f64>, Option<String>, Option<String>, Option<i32>, Option<i32>, Option<String>) = row.unwrap();
                let ts = epoch.map(|e| format!("{:.0}", e)).unwrap_or_default();
                let port = tcp_port.or(udp_port).map(|p| format!(":{}", p)).unwrap_or_default();
                let dns_str = dns.map(|d| format!(" [{}]", d)).unwrap_or_default();
                println!("  {} {} → {}{}{}", ts, src.unwrap_or_default(), dst.unwrap_or_default(), port, dns_str);
            }
        }
        "port" | "p" => {
            if arg.is_empty() { println!("Usage: port <number>"); return; }
            let port: i32 = match arg.parse() {
                Ok(p) if p > 0 && p <= 65535 => p,
                _ => { println!("Invalid port: '{}'. Must be 1-65535.", arg); return; }
            };
            let mut stmt = conn.prepare(
                "SELECT epoch, ip_src, ip_dst FROM packets WHERE tcp_dst_port = ?1 OR udp_dst_port = ?1 OR tcp_src_port = ?1 OR udp_src_port = ?1 ORDER BY epoch DESC LIMIT 100"
            ).unwrap();
            let rows = stmt.query_map(params![port], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            }).unwrap();
            println!("Traffic on port {}:", port);
            for row in rows {
                let (epoch, src, dst): (Option<f64>, Option<String>, Option<String>) = row.unwrap();
                let ts = epoch.map(|e| format!("{:.0}", e)).unwrap_or_default();
                println!("  {} {} → {}", ts, src.unwrap_or_default(), dst.unwrap_or_default());
            }
        }
        "dns" | "d" => {
            if arg.is_empty() { println!("Usage: dns <domain>"); return; }
            let pattern = format!("%{}%", arg);
            let mut stmt = conn.prepare(
                "SELECT DISTINCT dns_query, ip_src, COUNT(*) as cnt FROM packets WHERE dns_query LIKE ?1 GROUP BY dns_query ORDER BY cnt DESC LIMIT 50"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            }).unwrap();
            println!("DNS queries matching '{}':", arg);
            for row in rows {
                let (query, src, count): (String, Option<String>, u64) = row.unwrap();
                println!("  {} → {} (×{})", src.unwrap_or_default(), query, count);
            }
        }
        "find" | "f" | "search" | "s" => {
            if arg.is_empty() { println!("Usage: find <text>"); return; }
            let pattern = format!("%{}%", arg);
            let mut stmt = conn.prepare(
                "SELECT epoch, ip_src, ip_dst, dns_query, raw_json FROM packets WHERE raw_json LIKE ?1 OR dns_query LIKE ?1 OR ip_src LIKE ?1 OR ip_dst LIKE ?1 ORDER BY epoch DESC LIMIT 50"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            }).unwrap();
            println!("Results for '{}':", arg);
            for row in rows {
                let (epoch, src, dst, dns, _): (Option<f64>, Option<String>, Option<String>, Option<String>, Option<String>) = row.unwrap();
                let ts = epoch.map(|e| format!("{:.0}", e)).unwrap_or_default();
                let dns_str = dns.map(|d| format!(" [{}]", d)).unwrap_or_default();
                println!("  {} {} → {}{}", ts, src.unwrap_or_default(), dst.unwrap_or_default(), dns_str);
            }
        }
        "devices" => {
            let mut stmt = conn.prepare(
                "SELECT ip, mac, hostname, vendor, os_guess, ports FROM devices ORDER BY ip"
            ).unwrap();
            let rows = stmt.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            }).unwrap();
            println!("Known devices:");
            for row in rows {
                let (ip, _mac, hostname, _vendor, os_guess, ports): (String, Option<String>, Option<String>, Option<String>, Option<String>, String) = row.unwrap();
                println!("  {} ({}) — {} [{}]",
                    ip,
                    hostname.unwrap_or_default(),
                    os_guess.unwrap_or_default(),
                    if ports.is_empty() { "no ports".into() } else { ports });
            }
        }
        "stats" => {
            let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
            let devices: u64 = conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0);
            let dns: u64 = conn.query_row("SELECT COUNT(DISTINCT dns_query) FROM packets WHERE dns_query IS NOT NULL", [], |r| r.get(0)).unwrap_or(0);
            println!("Stats: {} packets, {} devices, {} DNS domains", total, devices, dns);
        }
        "talkers" | "top" => {
            let limit: usize = arg.parse().unwrap_or(20);
            let mut stmt = conn.prepare(
                "SELECT ip_src, COUNT(*) as cnt FROM packets GROUP BY ip_src ORDER BY cnt DESC LIMIT ?1"
            ).unwrap();
            let rows = stmt.query_map(params![limit as i64], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            println!("Top {} talkers:", limit);
            for row in rows {
                let (ip, count): (String, u64) = row.unwrap();
                println!("  {}: {} packets", ip, count);
            }
        }
        "recent" | "r" => {
            let limit: usize = arg.parse().unwrap_or(20);
            let mut stmt = conn.prepare(
                "SELECT epoch, ip_src, ip_dst, tcp_dst_port, dns_query FROM packets ORDER BY epoch DESC LIMIT ?1"
            ).unwrap();
            let rows = stmt.query_map(params![limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            }).unwrap();
            println!("Last {} packets:", limit);
            for row in rows {
                let (epoch, src, dst, port, dns): (Option<f64>, Option<String>, Option<String>, Option<i32>, Option<String>) = row.unwrap();
                let ts = epoch.map(|e| format!("{:.0}", e)).unwrap_or_default();
                let port_str = port.map(|p| format!(":{}", p)).unwrap_or_default();
                let dns_str = dns.map(|d| format!(" [{}]", d)).unwrap_or_default();
                println!("  {} {} → {}{}{}", ts, src.unwrap_or_default(), dst.unwrap_or_default(), port_str, dns_str);
            }
        }
        "connections" | "conn" => {
            if arg.is_empty() { println!("Usage: connections <ip>"); return; }
            let pattern = format!("%{}%", arg);

            // Outbound connections
            let mut stmt = conn.prepare(
                "SELECT ip_dst, COUNT(*) as cnt FROM packets WHERE ip_src LIKE ?1 GROUP BY ip_dst ORDER BY cnt DESC LIMIT 20"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            println!("{} connects to:", arg);
            for row in rows {
                let (ip, count): (String, u64) = row.unwrap();
                println!("  → {} (×{})", ip, count);
            }

            // Inbound connections
            let mut stmt = conn.prepare(
                "SELECT ip_src, COUNT(*) as cnt FROM packets WHERE ip_dst LIKE ?1 GROUP BY ip_src ORDER BY cnt DESC LIMIT 20"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            println!("\n{} connects from:", arg);
            for row in rows {
                let (ip, count): (String, u64) = row.unwrap();
                println!("  ← {} (×{})", ip, count);
            }
        }
        "services" | "svc" => {
            if arg.is_empty() { println!("Usage: services <ip>"); return; }
            let mut stmt = conn.prepare(
                "SELECT ports FROM devices WHERE ip LIKE ?1"
            ).unwrap();
            let rows = stmt.query_map(params![format!("%{}%", arg)], |r| r.get::<_, String>(0)).unwrap();
            for row in rows {
                let ports = row.unwrap();
                if !ports.is_empty() {
                    println!("Services on {}:\n  {}", arg, ports);
                } else {
                    println!("No port data for {}", arg);
                }
            }
        }
        _ => {
            println!("Unknown command: '{}'. Type 'help' for commands.", cmd);
        }
    }
}

fn run_ask(db_path: &Path, question: &str, model: &str) {
    let ctx = build_network_context(db_path);
    let context_str = format_context_for_ai(&ctx);
    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        eprintln!("[Error] Ollama not available");
        return;
    }
    let prompt = format!("{}\n\n## Question\n{}", context_str, question);
    match ollama.generate(&prompt) {
        Ok(response) => println!("{}", response),
        Err(e) => eprintln!("[Error] {}", e),
    }
}

fn run_report(db_path: &Path, model: &str) {
    let ctx = build_network_context(db_path);
    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        eprintln!("[Error] Ollama not available");
        return;
    }
    let findings_json = serde_json::to_string_pretty(&ctx.findings.iter().map(|f| {
        serde_json::json!({
            "ip": f.ip, "type": f.kind.to_string(),
            "confidence": format!("{:.0}%", f.confidence * 100.0),
            "detail": f.detail,
        })
    }).collect::<Vec<_>>()).unwrap_or_default();

    let prompt = format!("Generate a comprehensive network security report based on this data:\n\n{}\n\nDevices:\n{}\n\nFindings:\n{}",
        format_context_for_ai(&ctx),
        ctx.devices.iter().map(|(ip, _, h, _, _, p)| format!("{} ({}) [{}]", ip, h.as_deref().unwrap_or("?"), p)).collect::<Vec<_>>().join("\n"),
        findings_json);

    match ollama.generate(&prompt) {
        Ok(response) => println!("{}", response),
        Err(e) => eprintln!("[Error] {}", e),
    }
}

// ── Main ─────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let config = load_config();

    match cli.command {
        Commands::LiveInterpret { interface, duration, no_save, output, verbose, ai, model } => {
            let iface = interface.as_deref().unwrap_or(&config.interface);
            let dur = duration.unwrap_or(config.duration);
            let mdl = model.as_deref().unwrap_or(&config.ai.model);
            run_live_interpret(iface, dur, no_save, output.as_deref(), verbose, ai, mdl);
        }
        Commands::Capture { interface, target, duration, no_save, output, fast, no_nmap, no_tshark, debug } => {
            let iface = interface.as_deref().unwrap_or(&config.interface);
            let tgt = target.as_deref().unwrap_or(&config.target);
            let dur = duration.unwrap_or(config.duration);
            run_capture(iface, tgt, dur, no_save, output.as_deref(), fast, no_nmap, no_tshark, debug);
        }
        Commands::Chat { db, model } => {
            let db_path = db.unwrap_or_else(|| {
                let dir = dirs();
                let mut entries: Vec<_> = std::fs::read_dir(&dir).unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().map(|ext| ext == "db").unwrap_or(false))
                    .collect();
                entries.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
                entries.first().map(|e| e.path()).unwrap_or_else(|| {
                    eprintln!("[Error] No captures found. Run: correlator capture");
                    std::process::exit(1);
                })
            });
            let mdl = model.as_deref().unwrap_or(&config.ai.model);
            if !config.ai.enabled {
                println!("[System] AI disabled in config. Entering search mode.");
                run_search(&db_path, None);
            } else {
                run_chat(&db_path, mdl, false);
            }
        }
        Commands::Scan { target, output } => {
            let tgt = target.unwrap_or_else(|| {
                print!("Target CIDR (e.g. 192.168.1.0/24): ");
                io::stdout().flush().ok();
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                input.trim().to_string()
            });
            let db_path = default_db_path(false, output.as_deref());
            let conn = init_db(&db_path);
            let args = vec!["-sV", "-O", "-sC", "--open", "-oX", "-", "-T4", &tgt];
            let output = sudo_cmd("nmap").args(&args)
                .stdin(Stdio::inherit())
                .output().expect("Failed to run nmap");
            let xml_str = String::from_utf8_lossy(&output.stdout);
            if !xml_str.is_empty() {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
                let summary = parse_nmap_xml(&xml_str, &conn, now);
                conn.execute("INSERT INTO nmap_scans (target, scan_time, raw_xml, summary) VALUES (?1, ?2, ?3, ?4)",
                    params![tgt, now, xml_str.to_string(), summary.clone()]).unwrap();
                println!("{}", summary);
            }
            println!("[System] Saved to {}", db_path.display());
        }
        Commands::Query { sql, db } => run_query(&db, &sql, "table"),
        Commands::Stats { db } => run_stats(&db),
        Commands::Dns { db } => run_dns(&db),
        Commands::TopTalkers { db, limit } => run_top_talkers(&db, limit),
        Commands::Devices { db } => run_devices(&db),
        Commands::List => run_list(),
        Commands::Report { db, model } => run_report(&db, model.as_deref().unwrap_or(&config.ai.model)),
        Commands::Ask { db, question, model } => run_ask(&db, &question, model.as_deref().unwrap_or(&config.ai.model)),
        Commands::Search { db, query } => run_search(&db, query.as_deref()),
    }
}
