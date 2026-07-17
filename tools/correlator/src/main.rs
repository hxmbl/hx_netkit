use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use rusqlite::{Connection, params};
use serde_json::Value;

mod correlate;
use correlate::{Correlator, RealtimeEngine, OllamaClient, Packet, load_from_db, print_findings, print_profile};

// ── CLI ──────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "correlator", version, about = "tshark → SQLite → AI-powered network correlation engine")]
struct Cli {
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
        /// Run real-time correlation every 30s
        #[arg(long)]
        realtime: bool,
        /// AI model to use (default: qwen2.5-coder:1.5b)
        #[arg(long, default_value = "qwen2.5-coder:1.5b")]
        model: String,
    },

    /// Analyze a capture database with AI
    Analyze {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(long, default_value = "qwen2.5-coder:1.5b")]
        model: String,
        /// Show detailed profiles
        #[arg(long)]
        profiles: bool,
        /// Explain a specific IP
        #[arg(long)]
        ip: Option<String>,
        /// Skip AI, just show findings
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

    /// Ask AI about the network
    Ask {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(short, long)]
        question: String,
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
        CREATE INDEX IF NOT EXISTS idx_dns ON packets(dns_query);"
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
    drop(conn);

    let mut correlator = Correlator::new();
    correlator.ingest_batch(packets);
    let findings = correlator.correlate();

    let ollama = OllamaClient::new(model);
    if !ollama.is_available() {
        println!("[Error] Ollama not available at localhost:11434");
        std::process::exit(1);
    }

    // Build context
    let findings_summary: String = findings.iter().take(20).map(|f|
        format!("{} [{}] {}%: {}", f.ip, f.kind, (f.confidence * 100.0) as u32, f.detail)
    ).collect::<Vec<_>>().join("\n");

    let stats_summary = format!(
        "{} total packets, {} unique IPs, {} DNS domains",
        correlator.packet_count(),
        correlator.profiles().len(),
        correlator.profiles().values().map(|p| p.dns_domains.len()).sum::<usize>(),
    );

    let prompt = format!(
        "You are a network security analyst. Based on this network capture data:\n\n\
         ## Stats\n{}\n\n\
         ## Findings\n{}\n\n\
         ## Top IPs\n{}\n\n\
         ## Question\n{}\n\n\
         Answer the question based on the network data. Be specific and reference actual IPs and patterns.",
        stats_summary,
        findings_summary,
        correlator.profiles().iter().take(10).map(|(ip, p)|
            format!("{}: {} pkts, {} out, {} in, {} dns, {} domains",
                ip, p.packet_count, p.outbound_count, p.inbound_count, p.dns_count, p.dns_domains.len())
        ).collect::<Vec<_>>().join("\n"),
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

// ── Main ─────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Capture { interface, filter, output, realtime, model }) => {
            let iface = interface.unwrap_or_else(select_interface);
            println!("Starting capture on {}...", iface);
            run_capture(&iface, filter.as_deref(), output.as_deref().map(|p| p.to_str().unwrap_or("")), realtime, &model);
        }
        Some(Commands::Analyze { db, model, profiles, ip, offline }) => {
            run_analyze(&db, &model, profiles, ip.as_deref(), offline);
        }
        Some(Commands::Correlate { db, profiles, ip }) => {
            run_correlate(&db, profiles, ip.as_deref());
        }
        Some(Commands::Query { sql, db, format }) => { run_query(&db, &sql, &format); }
        Some(Commands::Stats { db }) => { run_stats(&db); }
        Some(Commands::Dns { db, unique }) => { run_dns(&db, unique); }
        Some(Commands::TopTalkers { db, limit }) => { run_top_talkers(&db, limit); }
        Some(Commands::List { dir }) => { run_list(&dir.unwrap_or_else(|| std::env::temp_dir())); }
        Some(Commands::Threat { db, model }) => { run_threat(&db, &model); }
        Some(Commands::Ask { db, question, model }) => { run_ask(&db, &question, &model); }
        None => { let i = select_interface(); println!("Starting on {}...", i); run_capture(&i, None, None, false, "qwen2.5-coder:1.5b"); }
    }
}
