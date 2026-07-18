use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand};
use rusqlite::{Connection, params};
use serde_json::Value;

mod correlate;
use correlate::{Correlator, RealtimeEngine, OllamaClient, Packet, load_from_db, print_findings, print_profile};

// ── CLI ──────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "correlator", version, about = "Network intelligence chatbot — scan, capture, analyze, chat")]
struct Cli {
    /// Skip nmap network scan
    #[arg(long)]
    no_nmap: bool,
    /// Skip tshark packet capture
    #[arg(long)]
    no_tshark: bool,
    /// Skip AI (Ollama) — offline mode only
    #[arg(long)]
    no_ai: bool,
    /// Fast scan — quicker nmap (no OS/version detection, top ports only)
    #[arg(long)]
    fast: bool,
    /// Target CIDR to scan with nmap (e.g. 192.168.1.0/24)
    #[arg(long)]
    target: Option<String>,
    /// Network interface for tshark (e.g. en1)
    #[arg(long)]
    interface: Option<String>,
    /// Capture duration in seconds (default: 300)
    #[arg(long, default_value_t = 300)]
    duration: u64,
    /// Output database path
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// AI model to use (default: qwen2.5-coder:1.5b)
    #[arg(long, default_value = "qwen2.5-coder:1.5b")]
    model: String,
    /// Resume from an existing database (skip scan+capture, go straight to chat)
    #[arg(short, long)]
    resume: Option<PathBuf>,
    /// Print raw tshark JSON to stderr for debugging
    #[arg(long)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture packets and correlate in real-time
    Capture {
        #[arg(short, long)]
        interface: Option<String>,
        #[arg(short, long)]
        filter: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        realtime: bool,
        #[arg(long, default_value = "qwen2.5-coder:1.5b")]
        model: String,
    },

    /// Analyze a capture database with AI
    Analyze {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(long, default_value = "qwen2.5-coder:1.5b")]
        model: String,
        #[arg(long)]
        profiles: bool,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        offline: bool,
    },

    /// Run correlation engine (no AI)
    Correlate {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(long)]
        profiles: bool,
        #[arg(long)]
        ip: Option<String>,
    },

    /// Query captured packets with SQL
    Query {
        sql: String,
        #[arg(short, long)]
        db: PathBuf,
        #[arg(short, long, default_value = "table")]
        format: String,
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
        #[arg(short, long, default_value_t = true)]
        unique: bool,
    },

    /// List top talkers
    TopTalkers {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },

    /// List capture databases
    List {
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },

    /// Threat assessment with AI
    Threat {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(long, default_value = "qwen2.5-coder:1.5b")]
        model: String,
    },

    /// Ask AI a single question about the network
    Ask {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(short, long)]
        question: String,
        #[arg(long, default_value = "qwen2.5-coder:1.5b")]
        model: String,
    },

    /// Scan network with nmap and store results
    Scan {
        #[arg(short, long)]
        target: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        interface: Option<String>,
    },

    /// List known devices from scans
    Devices {
        #[arg(short, long)]
        db: PathBuf,
    },

    /// Generate rich AI report from a capture database
    Report {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(long, default_value = "qwen2.5-coder:1.5b")]
        model: String,
    },
}

// ── Database ─────────────────────────────────────────────────

fn init_db(db_path: &Path) -> Connection {
    let conn = Connection::open(db_path).expect("Failed to open SQLite database");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch REAL, ip_src TEXT, ip_dst TEXT,
            tcp_src_port INTEGER, tcp_dst_port INTEGER,
            udp_src_port INTEGER, udp_dst_port INTEGER,
            dns_query TEXT, raw_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_epoch ON packets(epoch);
        CREATE INDEX IF NOT EXISTS idx_src ON packets(ip_src);
        CREATE INDEX IF NOT EXISTS idx_dst ON packets(ip_dst);
        CREATE INDEX IF NOT EXISTS idx_dns ON packets(dns_query);

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

// ── Nmap Scan ────────────────────────────────────────────────

fn run_scan(target: &str, output: Option<&Path>, interface: Option<&str>) {
    // Check nmap is installed
    if Command::new("nmap").arg("--version").stdout(Stdio::null()).status().is_err() {
        eprintln!("[Error] nmap not found. Install it: brew install nmap");
        std::process::exit(1);
    }

    let db_path = match output {
        Some(p) => p.to_path_buf(),
        None => std::env::temp_dir().join(format!("scan_{}.db", chrono_suffix())),
    };

    println!("[System] Target: {}", target);
    println!("[System] Database: {}", db_path.display());

    // Run nmap with OS detection, version detection, and script scanning
    println!("[System] Running nmap scan (this may take a while)...");
    let mut args = vec![
        "-sV",           // version detection
        "-O",            // OS detection
        "-sC",           // default scripts
        "--open",        // only show open ports
        "-oX", "-",      // XML output to stdout
        "-T4",           // aggressive timing
        target,
    ];

    let mut cmd = Command::new("sudo");
    cmd.arg("nmap").args(&args);

    // If interface specified, add it
    if let Some(iface) = interface {
        args.insert(0, "-e");
        args.insert(1, iface);
        cmd.arg("-e").arg(iface);
    }

    let output = cmd.output().expect("Failed to run nmap");
    let xml_str = String::from_utf8_lossy(&output.stdout);

    if xml_str.is_empty() {
        eprintln!("[Error] nmap produced no output");
        eprintln!("[Error] stderr: {}", String::from_utf8_lossy(&output.stderr));
        std::process::exit(1);
    }

    // Parse nmap XML output
    let conn = init_db(&db_path);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    // Store raw scan
    let summary = parse_nmap_xml(&xml_str, &conn, now);
    conn.execute(
        "INSERT INTO nmap_scans (target, scan_time, raw_xml, summary) VALUES (?1, ?2, ?3, ?4)",
        params![target, now, xml_str.to_string(), summary],
    ).expect("Failed to store scan");

    println!("\n[System] Scan complete. Results stored in {}", db_path.display());
}

fn parse_nmap_xml(xml: &str, conn: &Connection, scan_time: f64) -> String {
    let mut summary_lines = Vec::new();
    let mut current_ip: Option<String> = None;
    let mut current_mac: Option<String> = None;
    let mut current_hostname: Option<String> = None;
    let mut current_os: Option<String> = None;
    let mut current_vendor: Option<String> = None;
    let mut ports: Vec<String> = Vec::new();

    // Simple XML parsing (no dependency needed)
    for line in xml.lines() {
        let trimmed = line.trim();

        // Host start
        if trimmed.contains("<host ") && trimmed.contains("addr=") {
            // Extract addr
            if let Some(start) = trimmed.find("addr=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    let addr = &rest[..end];
                    if let Some(start2) = trimmed.find("addrtype=\"") {
                        let rest2 = &trimmed[start2 + 10..];
                        if let Some(end2) = rest2.find('"') {
                            let addr_type = &rest2[..end2];
                            if addr_type == "ipv4" {
                                // Flush previous host
                                if let Some(ip) = &current_ip {
                                    let ports_str = ports.join(", ");
                                    upsert_device(conn, ip, current_mac.as_deref(), current_hostname.as_deref(),
                                                  current_vendor.as_deref(), current_os.as_deref(), &ports_str, scan_time);
                                    summary_lines.push(format!("{} ({}) — {} [{}]", ip,
                                        current_hostname.as_deref().unwrap_or("unknown"),
                                        current_os.as_deref().unwrap_or("OS unknown"),
                                        if ports_str.is_empty() { "no open ports".into() } else { ports_str }));
                                }
                                current_ip = Some(addr.to_string());
                                current_mac = None;
                                current_hostname = None;
                                current_os = None;
                                current_vendor = None;
                                ports.clear();
                            }
                        }
                    }
                }
            }
        }

        // MAC address
        if trimmed.contains("<address ") && trimmed.contains("addrtype=\"mac\"") {
            if let Some(start) = trimmed.find("addr=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    current_mac = Some(rest[..end].to_string());
                }
            }
            if let Some(start) = trimmed.find("vendor=\"") {
                let rest = &trimmed[start + 8..];
                if let Some(end) = rest.find('"') {
                    current_vendor = Some(rest[..end].to_string());
                }
            }
        }

        // Hostname
        if trimmed.contains("<hostname name=") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    current_hostname = Some(rest[..end].to_string());
                }
            }
        }

        // OS detection
        if trimmed.contains("<osmatch ") {
            if let Some(start) = trimmed.find("name=\"") {
                let rest = &trimmed[start + 6..];
                if let Some(end) = rest.find('"') {
                    if current_os.is_none() {
                        current_os = Some(rest[..end].to_string());
                    }
                }
            }
        }

        // Port
        if trimmed.contains("<port ") && trimmed.contains("protocol=\"tcp\"") {
            let port_num = if let Some(start) = trimmed.find("portid=\"") {
                let rest = &trimmed[start + 8..];
                if let Some(end) = rest.find('"') { &rest[..end] } else { "?" }
            } else { "?" };

            let state = if let Some(start) = trimmed.find("state=\"") {
                let rest = &trimmed[start + 7..];
                if let Some(end) = rest.find('"') { &rest[..end] } else { "?" }
            } else { "?" };

            let service = "?";
            ports.push(format!("{}/{} {}", port_num, state, service));
        }

        // Service name (follows port)
        if trimmed.contains("<service ") && trimmed.contains("name=\"") {
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
    }

    // Flush last host
    if let Some(ip) = &current_ip {
        let ports_str = ports.join(", ");
        upsert_device(conn, ip, current_mac.as_deref(), current_hostname.as_deref(),
                      current_vendor.as_deref(), current_os.as_deref(), &ports_str, scan_time);
        summary_lines.push(format!("{} ({}) — {} [{}]", ip,
            current_hostname.as_deref().unwrap_or("unknown"),
            current_os.as_deref().unwrap_or("OS unknown"),
            if ports_str.is_empty() { "no open ports".into() } else { ports_str }));
    }

    summary_lines.join("\n")
}

fn upsert_device(conn: &Connection, ip: &str, mac: Option<&str>, hostname: Option<&str>,
                  vendor: Option<&str>, os_guess: Option<&str>, ports: &str, now: f64) {
    // Try to update existing, insert if new
    let rows = conn.execute(
        "UPDATE devices SET mac = COALESCE(?2, mac), hostname = COALESCE(?3, hostname),
         vendor = COALESCE(?4, vendor), os_guess = COALESCE(?5, os_guess), ports = ?6, last_seen = ?7
         WHERE ip = ?1",
        params![ip, mac, hostname, vendor, os_guess, ports, now],
    ).unwrap_or(0);

    if rows == 0 {
        conn.execute(
            "INSERT INTO devices (ip, mac, hostname, vendor, os_guess, ports, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![ip, mac, hostname, vendor, os_guess, ports, now],
        ).expect("Failed to insert device");
    }
}

fn run_devices(db_path: &Path) {
    let conn = open_db(db_path);
    let mut stmt = conn.prepare(
        "SELECT ip, mac, hostname, vendor, os_guess, ports, first_seen, last_seen FROM devices ORDER BY last_seen DESC"
    ).unwrap();

    let devices: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, String, f64, f64)> =
        stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
        }).unwrap().filter_map(|r| r.ok()).collect();

    if devices.is_empty() {
        println!("No devices found. Run 'correlator scan' first.");
        return;
    }

    println!("── Known Devices ({} total) ──\n", devices.len());
    println!("{:<16} {:<18} {:<25} {:<20} {}", "IP", "MAC", "Hostname", "OS", "Ports");
    println!("{}", "─".repeat(120));

    for (ip, mac, hostname, _vendor, os_guess, ports, _first, _last) in &devices {
        let mac_str = mac.as_deref().unwrap_or("-");
        let host_str = hostname.as_deref().unwrap_or("-");
        let os_str = os_guess.as_deref().unwrap_or("-");
        let ports_display = if ports.len() > 40 { format!("{}…", &ports[..37]) } else { ports.clone() };
        println!("{:<16} {:<18} {:<25} {:<20} {}", ip, mac_str, host_str, os_str, ports_display);
    }
}

// ── Report (rich AI analysis) ───────────────────────────────

fn run_report(db_path: &Path, model: &str) {
    let conn = open_db(db_path);
    let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    println!("[System] Loading {} packets...", total);
    let packets = load_from_db(&conn);

    let devices: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, String)> = {
        let mut stmt = conn.prepare(
            "SELECT ip, mac, hostname, vendor, os_guess, ports FROM devices"
        ).unwrap_or_else(|_| conn.prepare("SELECT ip, NULL, NULL, NULL, NULL, '' FROM devices").unwrap());
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap().filter_map(|r| r.ok()).collect()
    };

    let nmap_summaries: Vec<String> = {
        let mut stmt = conn.prepare("SELECT summary FROM nmap_scans ORDER BY scan_time DESC").unwrap_or_else(|_| {
            conn.prepare("SELECT '' FROM sqlite_master WHERE 0").unwrap()
        });
        stmt.query_map([], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect()
    };

    drop(conn);

    let mut correlator = Correlator::new();
    correlator.ingest_batch(packets);
    let findings = correlator.correlate_with_devices(&devices);

    println!("[System] {} IPs profiled, {} findings.", correlator.profiles().len(), findings.len());

    let cross_ref = correlator.cross_reference(&devices);

    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        println!("[System] Ollama not available. Attempting to start...");
        if !OllamaClient::try_start() {
            println!("[Error] Could not start Ollama. Install it: curl -fsSL https://ollama.com/install.sh | sh");
            println!("\n═══ OFFLINE FINDINGS ═══");
            print_findings(&findings);
            if !cross_ref.is_empty() {
                println!("\n═══ CROSS-REFERENCE ═══");
                println!("{}", cross_ref);
            }
            return;
        }
        println!("[System] Ollama started.");
    }

    println!("\n═══ GENERATING REPORT ═══");
    let report = ollama.generate_report(&findings, correlator.profiles(), &devices, &nmap_summaries, &cross_ref);
    println!("{}", report);
}

// ── Capture ──────────────────────────────────────────────────

fn run_capture(interface: &str, filter: Option<&str>, output: Option<&str>, realtime: bool, model: &str) {
    let db_path = match output {
        Some(p) => PathBuf::from(p),
        None => std::env::temp_dir().join(format!("capture_{}.db", chrono_suffix())),
    };

    println!("[System] Database: {}", db_path.display());
    println!("[System] Interface: {}", interface);
    if let Some(f) = filter { println!("[System] Filter: {}", f); }
    if realtime {
        let ollama = OllamaClient::new(model);
        let ai_status = if ollama.is_available() { "CONNECTED" } else { "UNAVAILABLE" };
        println!("[System] Real-time correlation: ON (AI: {})", ai_status);
    }

    let mut args = vec!["-i", interface, "-n", "-l", "-T", "ek",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "dns.qry.name"];
    if let Some(f) = filter { args.push("-f"); args.push(f); }

    let mut child = Command::new("sudo").args(["tshark"]).args(&args)
        .stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().expect("Failed to start tshark — is it installed?");

    if let Some(stdout_stream) = child.stdout.take() {
        let reader = std::io::BufReader::new(stdout_stream);
        let conn = init_db(&db_path);
        let mut insert_stmt = conn
            .prepare("INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
            .unwrap();

        let ollama = OllamaClient::new(model);
        let mut engine = RealtimeEngine::new(300); // 5-minute sliding window

        println!("Pipeline connected! Ingestion armed.");
        println!(">>> 's' toggle | 'a' analyze now | 'q' quit <<<\n");

        use crossterm::event::{self, Event, KeyCode, KeyEventKind};
        use std::io::BufRead;
        use std::time::Duration;

        crossterm::terminal::enable_raw_mode().expect("Failed to enable raw mode");

        let mut ingestion_enabled = true;
        let mut packet_count: u64 = 0;
        let mut stored_count: u64 = 0;
        let mut last_auto_analyze = std::time::Instant::now();
        let auto_interval = Duration::from_secs(30);

        for line_result in reader.lines() {
            // Keyboard handling
            if event::poll(Duration::from_millis(0)).unwrap() {
                if let Event::Key(key_event) = event::read().unwrap() {
                    if key_event.kind == KeyEventKind::Press {
                        match key_event.code {
                            KeyCode::Char('s') | KeyCode::Char('S') => {
                                ingestion_enabled = !ingestion_enabled;
                                let state = if ingestion_enabled { "ON" } else { "OFF" };
                                print!("\r\x1b[K[System] Ingestion: {}", state);
                                io::stdout().flush().ok();
                            }
                            KeyCode::Char('a') | KeyCode::Char('A') => {
                                // Manual analyze
                                crossterm::terminal::disable_raw_mode().ok();
                                println!("\n\n═══ MANUAL ANALYSIS ({} packets, {} in window) ═══", engine.packet_count(), engine.window_size());
                                let findings = engine.analyze();
                                print_findings(&findings);
                                if !ollama.is_available() {
                                    print!("\n[System] Ollama not running. Start it? [y/N] ");
                                    io::stdout().flush().ok();
                                    crossterm::terminal::enable_raw_mode().ok();
                                    // Read a single keypress
                                    if let Event::Key(key) = event::read().unwrap() {
                                        if key.code == KeyCode::Char('y') || key.code == KeyCode::Char('Y') {
                                            crossterm::terminal::disable_raw_mode().ok();
                                            print!("[System] Starting Ollama...");
                                            io::stdout().flush().ok();
                                            if OllamaClient::try_start() {
                                                println!(" OK");
                                                println!("\n── AI Analysis ──");
                                                let report = ollama.analyze_findings(&findings, engine.profiles());
                                                println!("{}", report);
                                            } else {
                                                println!(" FAILED (is 'ollama' installed?)");
                                            }
                                        }
                                    }
                                } else {
                                    println!("\n── AI Analysis ──");
                                    let report = ollama.analyze_findings(&findings, engine.profiles());
                                    println!("{}", report);
                                }
                                crossterm::terminal::enable_raw_mode().ok();
                            }
                            KeyCode::Char('q') | KeyCode::Char('Q') => {
                                println!("\r\x1b[K[System] Stopping...");
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
                    // Skip ES bulk action lines ({"index":{...}} or {"delete":{...}})
                    if raw_line.contains("\"index\"") && !raw_line.contains("\"_source\"") { continue; }
                    packet_count += 1;

                    if ingestion_enabled {
                        if let Ok(val) = serde_json::from_str::<Value>(&raw_line) {
                            let layers = val.get("_source")
                                .and_then(|s| s.get("layers"))
                                .or_else(|| val.get("layers"))
                                .and_then(|l| l.as_object());
                            let flat = if layers.is_none() { val.as_object() } else { None };
                            // Debug: print first few non-index lines to diagnose format
                            if stored_count == 0 && !raw_line.contains("\"index\"") {
                                eprintln!("[DEBUG] doc line keys: {:?}", val.as_object().map(|o| o.keys().collect::<Vec<_>>()));
                                if let Some(s) = val.get("_source") {
                                    eprintln!("[DEBUG] _source keys: {:?}", s.as_object().map(|o| o.keys().collect::<Vec<_>>()));
                                    if let Some(l) = s.get("layers") {
                                        eprintln!("[DEBUG] layers keys: {:?}", l.as_object().map(|o| o.keys().collect::<Vec<_>>()));
                                    }
                                }
                            }
                            let get_field = |name: &str| -> Option<&str> {
                                if let Some(l) = &layers {
                                    l.get(name).and_then(|v| v.as_str())
                                } else if let Some(f) = &flat {
                                    f.get(name).and_then(|v| v.as_str())
                                } else {
                                    None
                                }
                            };
                            let epoch = get_field("frame.time_epoch").and_then(|s| s.parse::<f64>().ok());
                            let ip_src = get_field("ip.src");
                            let ip_dst = get_field("ip.dst");
                            let tcp_src = get_field("tcp.srcport").and_then(|s| s.parse::<u32>().ok());
                            let tcp_dst = get_field("tcp.dstport").and_then(|s| s.parse::<u32>().ok());
                            let udp_src = get_field("udp.srcport").and_then(|s| s.parse::<u32>().ok());
                            let udp_dst = get_field("udp.dstport").and_then(|s| s.parse::<u32>().ok());
                            let dns_qry = get_field("dns.qry.name");

                            let _ = insert_stmt.execute(params![
                                epoch, ip_src, ip_dst, tcp_src, tcp_dst,
                                udp_src, udp_dst, dns_qry, raw_line.trim()
                            ]);
                            stored_count += 1;

                            engine.ingest(Packet {
                                epoch: epoch.unwrap_or(0.0),
                                ip_src: ip_src.map(|s| s.to_string()),
                                ip_dst: ip_dst.map(|s| s.to_string()),
                                tcp_src_port: tcp_src,
                                tcp_dst_port: tcp_dst,
                                udp_src_port: udp_src,
                                udp_dst_port: udp_dst,
                                dns_query: dns_qry.map(|s| s.to_string()),
                            });
                        }
                    }

                    if packet_count % 100 == 0 {
                        print!("\r\x1b[K  {} captured, {} stored, {} IPs, window: {}", packet_count, stored_count, engine.profiles().len(), engine.window_size());
                        io::stdout().flush().ok();
                    }

                    // Auto-analyze
                    if realtime && last_auto_analyze.elapsed() >= auto_interval {
                        if engine.should_analyze() {
                            crossterm::terminal::disable_raw_mode().ok();
                            println!("\n\n═══ AUTO ANALYSIS ({} pkts, {} IPs) ═══", engine.packet_count(), engine.profiles().len());
                            let findings = engine.analyze();
                            print_findings(&findings);

                            if !ollama.is_available() {
                                print!("\n[System] Ollama not running. Start it? [y/N] ");
                                io::stdout().flush().ok();
                                crossterm::terminal::enable_raw_mode().ok();
                                if let Event::Key(key) = event::read().unwrap() {
                                    if key.code == KeyCode::Char('y') || key.code == KeyCode::Char('Y') {
                                        crossterm::terminal::disable_raw_mode().ok();
                                        print!("[System] Starting Ollama...");
                                        io::stdout().flush().ok();
                                        if OllamaClient::try_start() {
                                            println!(" OK");
                                            if !findings.is_empty() {
                                                println!("\n── AI Threat Assessment ──");
                                                let report = ollama.threat_summary(&findings);
                                                println!("{}", report);
                                            }
                                        } else {
                                            println!(" FAILED (is 'ollama' installed?)");
                                        }
                                    }
                                }
                            } else if !findings.is_empty() {
                                println!("\n── AI Threat Assessment ──");
                                let report = ollama.threat_summary(&findings);
                                println!("{}", report);
                            }
                            crossterm::terminal::enable_raw_mode().ok();
                            last_auto_analyze = std::time::Instant::now();
                        }
                    }
                }
                Err(e) => { eprintln!("\n[System] Stream ended: {}", e); break; }
            }
        }

        crossterm::terminal::disable_raw_mode().unwrap();

        // Final analysis
        println!("\n═══ FINAL ANALYSIS ({} packets) ═══", engine.packet_count());
        let findings = engine.analyze();
        print_findings(&findings);

        if ollama.is_available() && !findings.is_empty() {
            println!("\n── AI Final Report ──");
            let report = ollama.analyze_findings(&findings, engine.profiles());
            println!("{}", report);
        }

        println!("\n[System] Done — {} captured, {} stored in {}", packet_count, stored_count, db_path.display());
    }

    let _ = child.kill();
    let _ = child.wait();
}

// ── Analyze (from DB with AI) ────────────────────────────────

fn run_analyze(db_path: &Path, model: &str, show_profiles: bool, filter_ip: Option<&str>, offline: bool) {
    let conn = open_db(db_path);
    let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    println!("[System] Loading {} packets...", total);
    let packets = load_from_db(&conn);
    drop(conn);

    let mut correlator = Correlator::new();
    correlator.ingest_batch(packets);
    let findings = correlator.correlate();

    println!("[System] {} IPs profiled.\n", correlator.profiles().len());

    if let Some(ip) = filter_ip {
        let filtered: Vec<_> = findings.iter().filter(|f| f.ip == ip).cloned().collect();
        print_findings(&filtered);
        if show_profiles {
            if let Some(profile) = correlator.profiles().get(&*ip) {
                println!();
                print_profile(profile);
            }
        }
    } else {
        print_findings(&findings);
        if show_profiles {
            println!("\n═══ PROFILES ═══");
            let mut profiles: Vec<_> = correlator.profiles().values().collect();
            profiles.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
            for profile in profiles.iter().take(15) {
                println!();
                print_profile(profile);
            }
        }
    }

    if offline { return; }

    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        println!("\n[System] Ollama not available at localhost:11434");
        return;
    }

    if let Some(ip) = filter_ip {
        if let Some(profile) = correlator.profiles().get(&*ip) {
            println!("\n── AI Analysis for {} ──", ip);
            let explanation = ollama.explain_ip(ip, profile, &findings);
            println!("{}", explanation);
        }
    } else {
        println!("\n── AI Threat Assessment ──");
        let report = ollama.threat_summary(&findings);
        println!("{}", report);

        println!("\n── AI Full Analysis ──");
        let full = ollama.analyze_findings(&findings, correlator.profiles());
        println!("{}", full);
    }
}

// ── Threat Assessment ────────────────────────────────────────

fn run_threat(db_path: &Path, model: &str) {
    let conn = open_db(db_path);
    let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    println!("[System] Loading {} packets...", total);
    let packets = load_from_db(&conn);
    drop(conn);

    let mut correlator = Correlator::new();
    correlator.ingest_batch(packets);
    let findings = correlator.correlate();

    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        println!("[System] Ollama not available. Showing offline findings:");
        print_findings(&findings);
        return;
    }

    println!("\n── AI Threat Assessment ──\n");
    let report = ollama.threat_summary(&findings);
    println!("{}", report);
}

// ── Ask AI ───────────────────────────────────────────────────

fn run_ask(db_path: &Path, question: &str, model: &str) {
    let conn = open_db(db_path);
    let _total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    let packets = load_from_db(&conn);

    // Load device data from nmap scans if available
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
    let findings = correlator.correlate();

    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        println!("[Error] Ollama not available at localhost:11434");
        std::process::exit(1);
    }

    // Build device context
    let device_summary = if devices.is_empty() {
        String::from("(no nmap scan data available — run 'correlator scan' first)")
    } else {
        devices.iter().map(|(ip, mac, hostname, vendor, os, ports)| {
            format!("IP: {} | MAC: {} | Host: {} | Vendor: {} | OS: {} | Ports: {}",
                ip,
                mac.as_deref().unwrap_or("?"),
                hostname.as_deref().unwrap_or("?"),
                vendor.as_deref().unwrap_or("?"),
                os.as_deref().unwrap_or("?"),
                if ports.is_empty() { "none".into() } else { ports.clone() })
        }).collect::<Vec<_>>().join("\n")
    };

    // Build findings context
    let findings_summary = if findings.is_empty() {
        String::from("(no findings)")
    } else {
        findings.iter().take(30).map(|f|
            format!("{} [{}] {}%: {}", f.ip, f.kind, (f.confidence * 100.0) as u32, f.detail)
        ).collect::<Vec<_>>().join("\n")
    };

    let stats_summary = format!(
        "{} total packets, {} unique IPs, {} DNS domains",
        correlator.packet_count(),
        correlator.profiles().len(),
        correlator.profiles().values().map(|p| p.dns_domains.len()).sum::<usize>(),
    );

    let profiles_summary: String = correlator.profiles().iter().take(20).map(|(ip, p)| {
        let dns = if p.dns_domains.is_empty() { String::new() } else { format!(", dns: {}", p.dns_domains.keys().take(5).cloned().collect::<Vec<_>>().join(",")) };
        let ports = if p.dest_ports.is_empty() { String::new() } else { format!(", ports: {}", p.dest_ports.iter().take(5).map(|(port, cnt)| format!("{}/{}", port, cnt)).collect::<Vec<_>>().join(",")) };
        format!("{}: {} pkts ({}↑ {}↓){}{}", ip, p.packet_count, p.outbound_count, p.inbound_count, dns, ports)
    }).collect::<Vec<_>>().join("\n");

    let prompt = format!(
        "You are a network security analyst analyzing a home/office network. You have access to BOTH traffic capture data AND nmap scan results.\n\n\
         ## Known Devices (from nmap)\n{}\n\n\
         ## Traffic Stats\n{}\n\n\
         ## IP Profiles\n{}\n\n\
         ## Detected Findings\n{}\n\n\
         ## Task\n\
         Answer the user's question about this network. Be specific:\n\
         - Identify devices by their role (router, phone, laptop, IoT, server, etc.) based on hostname, vendor, OS, ports, and traffic patterns\n\
         - Cross-reference nmap data with traffic data (e.g., device at 192.168.1.100 has port 80 open AND serves HTTP to other devices)\n\
         - Note any suspicious activity, unusual connections, or potential security concerns\n\
         - If you don't have enough data to answer definitively, say so and suggest what additional scans would help\n\n\
         ## Question\n{}",
        device_summary,
        stats_summary,
        profiles_summary,
        findings_summary,
        question,
    );

    println!("\n── AI Response ──\n");
    match ollama.generate(&prompt) {
        Ok(response) => println!("{}", response),
        Err(e) => eprintln!("[Error] {}", e),
    }
}

// ── Correlate (offline) ─────────────────────────────────────

fn run_correlate(db_path: &Path, show_profiles: bool, filter_ip: Option<&str>) {
    let conn = open_db(db_path);
    let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    println!("[System] Loading {} packets...", total);
    let packets = load_from_db(&conn);
    drop(conn);

    let mut correlator = Correlator::new();
    correlator.ingest_batch(packets);
    let findings = correlator.correlate();

    println!("[System] {} IPs profiled.\n", correlator.profiles().len());

    if let Some(ip) = filter_ip {
        let filtered: Vec<_> = findings.into_iter().filter(|f| f.ip == ip).collect();
        print_findings(&filtered);
        if show_profiles {
            if let Some(profile) = correlator.profiles().get(&*ip) { println!(); print_profile(profile); }
        }
    } else {
        print_findings(&findings);
        if show_profiles {
            println!("\n═══ PROFILES ═══");
            let mut profiles: Vec<_> = correlator.profiles().values().collect();
            profiles.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
            for profile in profiles.iter().take(20) { println!(); print_profile(profile); }
        }
    }
}

// ── Query ────────────────────────────────────────────────────

fn run_query(db_path: &Path, sql: &str, format: &str) {
    let conn = open_db(db_path);
    let query = if sql.starts_with('@') {
        std::fs::read_to_string(&sql[1..]).unwrap_or_else(|e| panic!("Failed to read query file: {}", e))
    } else { sql.to_string() };

    let mut stmt = match conn.prepare(&query) {
        Ok(s) => s,
        Err(e) => { eprintln!("[Error] SQL error: {}", e); std::process::exit(1); }
    };

    let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
    let mut rows = stmt.query([]).expect("Failed to execute query");

    match format {
        "json" => {
            let mut results = Vec::new();
            while let Some(row) = rows.next().unwrap() {
                let mut obj = serde_json::Map::new();
                for (i, col) in columns.iter().enumerate() {
                    let val: Option<String> = row.get(i).unwrap_or(None);
                    obj.insert(col.clone(), serde_json::Value::String(val.unwrap_or_default()));
                }
                results.push(serde_json::Value::Object(obj));
            }
            println!("{}", serde_json::to_string_pretty(&results).unwrap());
        }
        "csv" => {
            println!("{}", columns.join(","));
            while let Some(row) = rows.next().unwrap() {
                let vals: Vec<String> = (0..columns.len()).map(|i| row.get::<_, Option<String>>(i).unwrap_or(None).unwrap_or_default()).collect();
                println!("{}", vals.join(","));
            }
        }
        _ => {
            let mut widths: Vec<usize> = columns.iter().map(|c| c.len()).collect();
            let mut all_rows = Vec::new();
            while let Some(row) = rows.next().unwrap() {
                let vals: Vec<String> = (0..columns.len()).map(|i| row.get::<_, Option<String>>(i).unwrap_or(None).unwrap_or_default()).collect();
                for (i, v) in vals.iter().enumerate() { widths[i] = widths[i].max(v.len()); }
                all_rows.push(vals);
            }
            let header: Vec<String> = columns.iter().enumerate().map(|(i, c)| format!("{:<width$}", c, width = widths[i])).collect();
            let sep: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
            println!("{}", header.join(" │ "));
            println!("{}", sep.join("─┼─"));
            for vals in &all_rows {
                let cells: Vec<String> = vals.iter().enumerate().map(|(i, v)| format!("{:<width$}", v, width = widths[i])).collect();
                println!("{}", cells.join(" │ "));
            }
            println!("\n({} rows)", all_rows.len());
        }
    }
}

// ── Stats ────────────────────────────────────────────────────

fn run_stats(db_path: &Path) {
    let conn = open_db(db_path);
    let total: u64 = conn.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0)).unwrap_or(0);
    let with_ip: u64 = conn.query_row("SELECT COUNT(*) FROM packets WHERE ip_src IS NOT NULL", [], |r| r.get(0)).unwrap_or(0);
    let with_dns: u64 = conn.query_row("SELECT COUNT(*) FROM packets WHERE dns_query IS NOT NULL", [], |r| r.get(0)).unwrap_or(0);
    let time_range: (Option<f64>, Option<f64>) = conn.query_row("SELECT MIN(epoch), MAX(epoch) FROM packets", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or((None, None));

    println!("╔══════════════════════════════════════╗");
    println!("║         Capture Statistics           ║");
    println!("╠══════════════════════════════════════╣");
    println!("║  Total packets:    {:<18}║", total);
    println!("║  With IP:          {:<18}║", with_ip);
    println!("║  DNS queries:      {:<18}║", with_dns);
    if let (Some(start), Some(end)) = time_range {
        let duration = end - start;
        println!("║  Duration:         {:<15.1}s  ║", duration);
        if duration > 0.0 { println!("║  Packets/sec:      {:<15.1}   ║", total as f64 / duration); }
    }
    println!("╚══════════════════════════════════════╝");
}

// ── DNS ──────────────────────────────────────────────────────

fn run_dns(db_path: &Path, unique_only: bool) {
    let conn = open_db(db_path);
    let query = if unique_only {
        "SELECT dns_query, COUNT(*) as cnt FROM packets WHERE dns_query IS NOT NULL GROUP BY dns_query ORDER BY cnt DESC"
    } else {
        "SELECT dns_query, 1 as cnt FROM packets WHERE dns_query IS NOT NULL ORDER BY epoch"
    };
    let mut stmt = conn.prepare(query).unwrap();
    let rows: Vec<(String, u64)> = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(|r| r.ok()).collect();
    if rows.is_empty() { println!("(no DNS queries)"); return; }
    println!("{:<50} {:>6}", "DNS Query", "Count");
    println!("{}", "─".repeat(58));
    for (q, c) in &rows { if *c > 1 { println!("{:<50} {:>6}", q, c); } else { println!("{:<50}", q); } }
    println!("\n({})", rows.len());
}

// ── Top Talkers ──────────────────────────────────────────────

fn run_top_talkers(db_path: &Path, limit: usize) {
    let conn = open_db(db_path);
    let mut stmt = conn.prepare("SELECT ip, SUM(cnt) as total FROM (SELECT ip_src as ip, COUNT(*) as cnt FROM packets WHERE ip_src IS NOT NULL GROUP BY ip_src UNION ALL SELECT ip_dst as ip, COUNT(*) as cnt FROM packets WHERE ip_dst IS NOT NULL GROUP BY ip_dst) GROUP BY ip ORDER BY total DESC LIMIT ?1").unwrap();
    let rows: Vec<(String, u64)> = stmt.query_map(params![limit as u64], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(|r| r.ok()).collect();
    if rows.is_empty() { println!("(none)"); return; }
    let max = rows[0].1;
    println!("── Top Talkers ──\n");
    for (ip, cnt) in &rows {
        let bar = "█".repeat((*cnt as usize * 40) / (max as usize).max(1));
        println!("  {:<20} {:>8}  {}", ip, cnt, bar);
    }
}

// ── List ─────────────────────────────────────────────────────

fn run_list(dir: &Path) {
    let entries: Vec<PathBuf> = std::fs::read_dir(dir).unwrap_or_else(|e| { eprintln!("[Error] {}", e); std::process::exit(1); })
        .filter_map(|e| e.ok()).map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("capture_") && n.ends_with(".db")).unwrap_or(false))
        .collect();
    if entries.is_empty() { println!("No captures in {}", dir.display()); return; }
    let mut sorted = entries; sorted.sort(); sorted.reverse();
    for e in &sorted {
        let size = std::fs::metadata(e).ok().map(|m| m.len()).unwrap_or(0);
        let size_str = if size > 1024*1024 { format!("{:.1} MB", size as f64/(1024.0*1024.0)) } else if size > 1024 { format!("{:.1} KB", size as f64/1024.0) } else { format!("{} B", size) };
        let count = Connection::open(e).ok().and_then(|c| c.query_row("SELECT COUNT(*) FROM packets", [], |r| r.get::<_, u64>(0)).ok());
        println!("  {}  {:>10}  {}", e.display(), size_str, count.map(|c| format!("{} pkts", c)).unwrap_or_default());
    }
}

// ── Helpers ──────────────────────────────────────────────────

fn select_interface() -> String {
    let output = Command::new("tshark").arg("-D").output().expect("tshark not found");
    let list = String::from_utf8_lossy(&output.stdout);
    println!("{}\nEnter interface: ", list);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let clean = input.trim().to_string();
    if clean.is_empty() || !list.contains(&clean) { eprintln!("Invalid interface"); std::process::exit(1); }
    clean
}

fn chrono_suffix() -> String {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs().to_string()
}

// ── Chat Context Builder ─────────────────────────────────────

struct NetworkContext {
    devices: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, String)>,
    findings: Vec<correlate::Finding>,
    profiles: std::collections::HashMap<String, correlate::IpProfile>,
    cross_ref: String,
    packet_count: usize,
}

fn build_network_context(db_path: &Path) -> NetworkContext {
    let conn = open_db(db_path);
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

    // Device inventory
    if !ctx.devices.is_empty() {
        parts.push(format!("## Known Devices ({})\n{}", ctx.devices.len(),
            ctx.devices.iter().map(|(ip, mac, hostname, vendor, os, ports)| {
                format!("{} | MAC: {} | Host: {} | Vendor: {} | OS: {} | Ports: {}",
                    ip,
                    mac.as_deref().unwrap_or("?"),
                    hostname.as_deref().unwrap_or("?"),
                    vendor.as_deref().unwrap_or("?"),
                    os.as_deref().unwrap_or("?"),
                    if ports.is_empty() { "none" } else { ports })
            }).collect::<Vec<_>>().join("\n")));
    }

    // Stats
    let total_dns: usize = ctx.profiles.values().map(|p| p.dns_domains.len()).sum();
    parts.push(format!("## Traffic Stats\n{} packets, {} unique IPs, {} DNS domains, {} findings",
        ctx.packet_count, ctx.profiles.len(), total_dns, ctx.findings.len()));

    // Top profiles
    let mut profiles: Vec<_> = ctx.profiles.values().collect();
    profiles.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    if !profiles.is_empty() {
        parts.push(format!("## Top IPs\n{}",
            profiles.iter().take(20).map(|p| {
                let dns = if p.dns_domains.is_empty() { String::new() } else { format!(", dns: {}", p.dns_domains.keys().take(5).cloned().collect::<Vec<_>>().join(",")) };
                let ports = if p.dest_ports.is_empty() { String::new() } else { format!(", ports: {}", p.dest_ports.iter().take(5).map(|(port, cnt)| format!("{}/{}", port, cnt)).collect::<Vec<_>>().join(",")) };
                format!("{}: {} pkts ({}↑ {}↓){}{}", p.ip, p.packet_count, p.outbound_count, p.inbound_count, dns, ports)
            }).collect::<Vec<_>>().join("\n")));
    }

    // Findings
    if !ctx.findings.is_empty() {
        parts.push(format!("## Detected Findings\n{}",
            ctx.findings.iter().take(30).map(|f|
                format!("{} [{}] {}%: {}", f.ip, f.kind, (f.confidence * 100.0) as u32, f.detail)
            ).collect::<Vec<_>>().join("\n")));
    }

    // Cross-reference
    if !ctx.cross_ref.is_empty() {
        parts.push(format!("## Cross-Reference\n{}", ctx.cross_ref));
    }

    parts.join("\n\n")
}

// ── Chat Loop ────────────────────────────────────────────────

fn run_chat(db_path: &Path, model: &str) {
    println!("\n═══════ NETWORK INTELLIGENCE CHATBOT ═══════");
    println!("[System] Building context from {}", db_path.display());

    let ctx = build_network_context(db_path);
    let context_str = format_context_for_ai(&ctx);

    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        println!("[System] Ollama not available. Attempting to start...");
        if OllamaClient::try_start() {
            println!("[System] Ollama started.");
        } else {
            println!("[Error] Could not start Ollama. Install: curl -fsSL https://ollama.com/install.sh | sh");
            println!("[System] Entering offline mode — showing findings only.\n");
            print_findings(&ctx.findings);
            return;
        }
    }

    // System prompt for the chat session
    let system_prompt = format!(
        "You are a senior network security analyst with FULL VISIBILITY into this network. \
         You have been given complete data from nmap scanning and live packet capture.\n\n\
         {}\n\n\
         ## Your Role\n\
         You are an interactive analyst. The user will ask you questions about this network. \
         Answer thoroughly, cross-referencing all data sources. Be specific — use actual IPs, \
         ports, hostnames, and timestamps. Don't just list findings — INTERPRET them. \
         What story does this data tell? What is normal? What is suspicious?\n\n\
         You can:\n\
         - Identify any device by IP, hostname, or role\n\
         - Explain traffic patterns between devices\n\
         - Assess security threats and anomalies\n\
         - Suggest what to investigate further\n\
         - Run hypothetical scenarios\n\
         - Compare devices and their behaviors\n\n\
         Be concise but thorough. Use the data, not guesses.",
        context_str
    );

    println!("\n[System] Chat ready. {} devices, {} packets, {} findings loaded.",
        ctx.devices.len(), ctx.packet_count, ctx.findings.len());
    println!("[System] Type your question. 'quit' or Ctrl+C to exit.\n");

    let mut conversation: Vec<(String, String)> = Vec::new();

    loop {
        print!("you> ");
        io::stdout().flush().ok();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => { eprintln!("[Error] {}", e); break; }
        }

        let question = input.trim().to_string();
        if question.is_empty() { continue; }
        if question == "quit" || question == "exit" || question == "q" { break; }

        // Build prompt with conversation history
        let mut prompt = format!("{}\n\n## Conversation\n", system_prompt);

        // Include last 5 exchanges for context
        let start = conversation.len().saturating_sub(5);
        for (q, a) in &conversation[start..] {
            prompt.push_str(&format!("User: {}\nAssistant: {}\n\n", q, a));
        }
        prompt.push_str(&format!("User: {}\nAssistant:", question));

        print!("  ");
        io::stdout().flush().ok();

        match ollama.generate(&prompt) {
            Ok(response) => {
                println!("{}", response);
                conversation.push((question, response));
            }
            Err(e) => {
                eprintln!("\n[Error] {}", e);
                println!("  [AI unavailable — try again or 'quit']");
            }
        }
        println!();
    }

    println!("\n[System] Chat ended. {} exchanges recorded.", conversation.len());
}

// ── Main ─────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // If a subcommand was given, dispatch to it
    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Capture { interface, filter, output, realtime, model } => {
                let iface = interface.unwrap_or_else(select_interface);
                println!("Starting capture on {}...", iface);
                run_capture(&iface, filter.as_deref(), output.as_deref().map(|p| p.to_str().unwrap_or("")), realtime, &model);
            }
            Commands::Analyze { db, model, profiles, ip, offline } => {
                run_analyze(&db, &model, profiles, ip.as_deref(), offline);
            }
            Commands::Correlate { db, profiles, ip } => {
                run_correlate(&db, profiles, ip.as_deref());
            }
            Commands::Query { sql, db, format } => { run_query(&db, &sql, &format); }
            Commands::Stats { db } => { run_stats(&db); }
            Commands::Dns { db, unique } => { run_dns(&db, unique); }
            Commands::TopTalkers { db, limit } => { run_top_talkers(&db, limit); }
            Commands::List { dir } => { run_list(&dir.unwrap_or_else(|| std::env::temp_dir())); }
            Commands::Threat { db, model } => { run_threat(&db, &model); }
            Commands::Ask { db, question, model } => { run_ask(&db, &question, &model); }
            Commands::Scan { target, output, interface } => { run_scan(&target, output.as_deref(), interface.as_deref()); }
            Commands::Devices { db } => { run_devices(&db); }
            Commands::Report { db, model } => { run_report(&db, &model); }
        }
        return;
    }

    // ── Default: Chatbot mode ──

    // If --resume, skip straight to chat
    if let Some(db_path) = &cli.resume {
        if !db_path.exists() {
            eprintln!("[Error] Database not found: {}", db_path.display());
            std::process::exit(1);
        }
        run_chat(db_path, &cli.model);
        return;
    }

    // Validate we have something to do
    if cli.no_nmap && cli.no_tshark {
        eprintln!("[Error] Can't do anything with --no-nmap --no-tshark. Use --resume with an existing .db");
        std::process::exit(1);
    }

    // Need interface for tshark
    let interface = if cli.no_tshark {
        None
    } else {
        Some(cli.interface.clone().unwrap_or_else(select_interface))
    };

    // Need target for nmap
    let target = if cli.no_nmap {
        None
    } else {
        match &cli.target {
            Some(t) => Some(t.clone()),
            None => {
                // Auto-detect: try to get local network from default route
                print!("Enter scan target (e.g. 192.168.1.0/24): ");
                io::stdout().flush().ok();
                let mut input = String::new();
                io::stdin().read_line(&mut input).ok();
                let t = input.trim().to_string();
                if t.is_empty() {
                    eprintln!("[Error] Target required for nmap scan");
                    std::process::exit(1);
                }
                Some(t)
            }
        }
    };

    let db_path = match &cli.output {
        Some(p) => p.to_path_buf(),
        None => std::env::temp_dir().join(format!("monitor_{}.db", chrono_suffix())),
    };

    // ═══ PHASE 1: SCAN ═══
    if let Some(ref target) = target {
        if cli.no_nmap { /* skip */ } else {
            println!("\n═══════ PHASE 1: NETWORK SCAN ═══════");
            println!("[System] Target: {}", target);
            println!("[System] Database: {}\n", db_path.display());

            if Command::new("nmap").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_err() {
                eprintln!("[Warning] nmap not found — skipping scan. Install: brew install nmap");
            } else {
                let args = if cli.fast {
                    // Fast: SYN scan, top 100 ports, no OS/version detection
                    vec!["-sS", "--top-ports", "100", "--open", "-oX", "-", "-T4", "--min-rate", "1000", target.as_str()]
                } else {
                    // Thorough: version + OS + scripts
                    vec!["-sV", "-O", "-sC", "--open", "-oX", "-", "-T4", target.as_str()]
                };
                let output = Command::new("sudo").arg("nmap").args(&args)
                    .stdin(std::process::Stdio::inherit())
                    .output().expect("Failed to run nmap");
                let xml_str = String::from_utf8_lossy(&output.stdout);
                let stderr_str = String::from_utf8_lossy(&output.stderr);

                if !stderr_str.is_empty() {
                    eprintln!("[nmap stderr] {}", stderr_str);
                }

                if xml_str.is_empty() {
                    eprintln!("[nmap] Empty output (exit code: {:?}). nmap may need sudo.", output.status);
                } else if !xml_str.contains("<host") {
                    eprintln!("[nmap] XML has no <host> entries. Scan found nothing.");
                    eprintln!("[nmap] Raw (first 500 chars): {}", &xml_str[..xml_str.len().min(500)]);
                }

                if !xml_str.is_empty() {
                    let conn = init_db(&db_path);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64();
                    let summary = parse_nmap_xml(&xml_str, &conn, now);
                    conn.execute(
                        "INSERT INTO nmap_scans (target, scan_time, raw_xml, summary) VALUES (?1, ?2, ?3, ?4)",
                        params![target, now, xml_str.to_string(), summary.clone()],
                    ).expect("Failed to store scan");
                    let device_count: u64 = conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0);
                    println!("[System] Found {} devices:", device_count);
                    println!("{}", summary);
                } else {
                    eprintln!("[Warning] nmap produced no output");
                }
            }
        }
    }

    // ═══ PHASE 2: CAPTURE ═══
    if !cli.no_tshark {
        if let Some(ref iface) = interface {
            println!("\n═══════ PHASE 2: PACKET CAPTURE ═══════");
            println!("[System] Interface: {}", iface);
            println!("[System] Duration: {}s", cli.duration);
            println!("[System] Press 'q' to stop early\n");

            let tshark_args = vec![
                "-i", iface, "-n", "-l", "-T", "ek",
                "-f", "not host 127.0.0.1",
                "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
                "-e", "tcp.srcport", "-e", "tcp.dstport",
                "-e", "udp.srcport", "-e", "udp.dstport", "-e", "dns.qry.name",
            ];

            let mut child = Command::new("sudo").args(["tshark"]).args(&tshark_args)
                .stdout(Stdio::piped()).stderr(Stdio::null())
                .spawn().expect("Failed to start tshark — is it installed?");

            // Timer thread to kill tshark after duration
            let child_pid = child.id();
            let timer_handle = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(cli.duration));
                let _ = Command::new("sudo").args(["kill", "-INT"]).arg(child_pid.to_string()).output();
            });

            if let Some(stdout_stream) = child.stdout.take() {
                let reader = std::io::BufReader::new(stdout_stream);
                let conn = if db_path.exists() {
                    open_db(&db_path)
                } else {
                    init_db(&db_path)
                };
                let mut insert_stmt = conn
                    .prepare("INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
                    .unwrap();

                let mut packet_count: u64 = 0;
                let mut stored_count: u64 = 0;
                let mut ips_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut dns_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                let capture_start = std::time::Instant::now();

                use crossterm::event::{self, Event, KeyCode, KeyEventKind};
                use std::io::BufRead;

                crossterm::terminal::enable_raw_mode().expect("Failed to enable raw mode");

                let mut early_exit = false;

                for line_result in reader.lines() {
                    if event::poll(Duration::from_millis(0)).unwrap() {
                        if let Event::Key(key_event) = event::read().unwrap() {
                            if key_event.kind == KeyEventKind::Press {
                                match key_event.code {
                                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                                        println!("\r\x1b[K[System] Stopping early...");
                                        early_exit = true;
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
                            packet_count += 1;

                            if let Ok(val) = serde_json::from_str::<Value>(&raw_line) {
                                let layers = val.get("_source")
                                    .and_then(|s| s.get("layers"))
                                    .or_else(|| val.get("layers"))
                                    .and_then(|l| l.as_object());
                                let flat = if layers.is_none() { val.as_object() } else { None };

                                // Debug: print first 3 parsed packets
                                if cli.debug && stored_count < 3 {
                                    eprintln!("[DEBUG] ── packet {} ──", stored_count);
                                    eprintln!("[DEBUG] raw: {}", &raw_line[..raw_line.len().min(500)]);
                                    if let Some(l) = &layers {
                                        eprintln!("[DEBUG] layers keys: {:?}", l.keys().collect::<Vec<_>>());
                                        if let Some(f) = l.get("frame") { eprintln!("[DEBUG] frame: {:?}", f); }
                                        if let Some(f) = l.get("ip") { eprintln!("[DEBUG] ip: {:?}", f); }
                                        if let Some(f) = l.get("tcp") { eprintln!("[DEBUG] tcp: {:?}", f); }
                                        if let Some(f) = l.get("dns") { eprintln!("[DEBUG] dns: {:?}", f); }
                                    } else if let Some(f) = &flat {
                                        eprintln!("[DEBUG] flat keys: {:?}", f.keys().collect::<Vec<_>>());
                                    } else {
                                        eprintln!("[DEBUG] NO layers or flat found!");
                                        eprintln!("[DEBUG] top-level keys: {:?}", val.as_object().map(|o| o.keys().collect::<Vec<_>>()));
                                    }
                                }

                                let get_field = |name: &str| -> Option<&str> {
                                    // Try both formats: tshark <4.6 uses dots (ip.src), 4.6+ uses underscores (ip_src)
                                    // Also try as array value: ["value"] → "value"
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
                                let epoch = get_field("frame.time_epoch").and_then(|s| s.parse::<f64>().ok());
                                let ip_src = get_field("ip.src");
                                let ip_dst = get_field("ip.dst");
                                let tcp_src = get_field("tcp.srcport").and_then(|s| s.parse::<u32>().ok());
                                let tcp_dst = get_field("tcp.dstport").and_then(|s| s.parse::<u32>().ok());
                                let udp_src = get_field("udp.srcport").and_then(|s| s.parse::<u32>().ok());
                                let udp_dst = get_field("udp.dstport").and_then(|s| s.parse::<u32>().ok());
                                let dns_qry = get_field("dns.qry.name");

                                if let Some(s) = ip_src { ips_seen.insert(s.to_string()); }
                                if let Some(d) = ip_dst { ips_seen.insert(d.to_string()); }
                                if let Some(d) = dns_qry { dns_seen.insert(d.to_string()); }

                                let _ = insert_stmt.execute(params![
                                    epoch, ip_src, ip_dst, tcp_src, tcp_dst,
                                    udp_src, udp_dst, dns_qry, raw_line.trim()
                                ]);
                                stored_count += 1;
                            }

                            if packet_count % 100 == 0 {
                                let elapsed = capture_start.elapsed().as_secs();
                                print!("\r\x1b[K  {} captured, {} stored, {} IPs, {} DNS, {}s elapsed  ",
                                    packet_count, stored_count, ips_seen.len(), dns_seen.len(), elapsed);
                                io::stdout().flush().ok();
                            }
                        }
                        Err(_) => { break; }
                    }
                }

                crossterm::terminal::disable_raw_mode().ok();
                let _ = child.kill();
                let _ = child.wait();
                let _ = timer_handle.join();

                if early_exit {
                    println!("\n[System] Capture stopped early — {} packets captured, {} stored", packet_count, stored_count);
                } else {
                    println!("\n\n═══ CAPTURE COMPLETE ═══");
                    println!("[System] {} packets captured, {} stored", packet_count, stored_count);
                    println!("[System] {} unique IPs, {} DNS domains", ips_seen.len(), dns_seen.len());
                }
            }
        }
    }

    // ═══ PHASE 3: CHAT ═══
    if cli.no_ai {
        println!("\n═══ OFFLINE MODE ═══");
        let ctx = build_network_context(&db_path);
        print_findings(&ctx.findings);
        if !ctx.cross_ref.is_empty() {
            println!("\n═══ CROSS-REFERENCE ═══");
            println!("{}", ctx.cross_ref);
        }
        println!("\n[System] Database saved at {}", db_path.display());
        println!("[System] To chat with AI, run: correlator --resume {}", db_path.display());
    } else {
        run_chat(&db_path, &cli.model);
    }
}
