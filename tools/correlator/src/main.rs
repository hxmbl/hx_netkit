#![allow(dead_code)]

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod config;
mod constants;
mod db;
mod tshark;
mod tools;
mod search;
mod context;
mod live;
mod capture;
mod chat;
mod correlate;
mod scanner;

use config::{load_config, resolve_model};
use correlate::OllamaClient;
use scanner::BeliefSystem;

use std::sync::OnceLock;
static BELIEFS: OnceLock<std::sync::Arc<std::sync::Mutex<BeliefSystem>>> = OnceLock::new();

// ── CLI ──

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
        #[arg(short, long)]
        interface: Option<String>,
        #[arg(long)]
        duration: Option<u64>,
        #[arg(long)]
        no_save: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long)]
        verbose: bool,
        #[arg(long)]
        ai: bool,
        #[arg(long)]
        model: Option<String>,
    },

    /// Capture packets + nmap scan in parallel, store metadata
    Capture {
        #[arg(short, long)]
        interface: Option<String>,
        #[arg(short, long)]
        target: Option<String>,
        #[arg(long)]
        duration: Option<u64>,
        #[arg(long)]
        no_save: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        fast: bool,
        #[arg(long)]
        no_nmap: bool,
        #[arg(long)]
        no_tshark: bool,
        #[arg(long)]
        debug: bool,
        /// Stealth level: 0=full scan (default), 1=light, 2=passive (no scanning)
        #[arg(long, default_value_t = 0)]
        stealth_level: u8,
    },

    /// Chat with AI about captured network data
    Chat {
        #[arg(short, long)]
        db: Option<PathBuf>,
        #[arg(long)]
        model: Option<String>,
        /// Stealth level: 0=full (default), 1=light, 2=passive
        #[arg(long, default_value_t = 0)]
        stealth_level: u8,
    },

    /// Run nmap scan only
    Scan {
        #[arg(short, long)]
        target: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Search network data — no AI, just smart queries
    Search {
        #[arg(short, long)]
        db: PathBuf,
        #[arg(short, long)]
        query: Option<String>,
    },

    /// Query captured packets with SQL
    Query {
        sql: String,
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

// ── Utility Commands ──

fn run_query(db_path: &std::path::Path, sql: &str, format: &str) {
    let conn = db::open_db(db_path);
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

fn run_stats(db_path: &std::path::Path) {
    let conn = db::open_db(db_path);
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

fn run_dns(db_path: &std::path::Path) {
    let conn = db::open_db(db_path);
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

fn run_top_talkers(db_path: &std::path::Path, limit: usize) {
    let conn = db::open_db(db_path);
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

fn run_devices(db_path: &std::path::Path) {
    let conn = db::open_db(db_path);
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
    let dir = config::dirs();
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

fn run_ask(db_path: &std::path::Path, question: &str, model: &str) {
    let ctx = context::build_network_context(db_path);
    let context_str = context::format_context_for_ai(&ctx);
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

fn run_report(db_path: &std::path::Path, model: &str) {
    let ctx = context::build_network_context(db_path);
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
        context::format_context_for_ai(&ctx),
        ctx.devices.iter().map(|(ip, _, h, _, _, p)| format!("{} ({}) [{}]", ip, h.as_deref().unwrap_or("?"), p)).collect::<Vec<_>>().join("\n"),
        findings_json);

    match ollama.generate(&prompt) {
        Ok(response) => println!("{}", response),
        Err(e) => eprintln!("[Error] {}", e),
    }
}

// ── Main ──

fn main() {
    let cli = Cli::parse();
    let config = load_config();

    match cli.command {
        Commands::LiveInterpret { interface, duration, no_save, output, verbose, ai, model } => {
            let iface = interface.as_deref().unwrap_or(&config.interface);
            let dur = duration.unwrap_or(config.duration);
            let mdl = resolve_model(model.as_deref(), &config);
            live::run_live_interpret(iface, dur, no_save, output.as_deref(), verbose, ai, mdl);
        }
        Commands::Capture { interface, target, duration, no_save, output, fast, no_nmap, no_tshark, debug, stealth_level } => {
            let iface = interface.as_deref().unwrap_or(&config.interface);
            let tgt = target.as_deref().unwrap_or(&config.target);
            let dur = duration.unwrap_or(config.duration);
            capture::run_capture(iface, tgt, dur, no_save, output.as_deref(), fast, no_nmap, no_tshark, debug, stealth_level);
        }
        Commands::Chat { db, model, stealth_level } => {
            let db_path = db.unwrap_or_else(|| {
                let dir = config::dirs();
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
            let mdl = resolve_model(model.as_deref(), &config);
            if !config.ai.enabled {
                println!("[System] AI disabled in config. Entering search mode.");
                search::run_search(&db_path, None);
            } else {
                chat::run_chat(&db_path, mdl, false, stealth_level);
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
            let db_path = db::default_db_path(false, output.as_deref());
            let conn = db::init_db(&db_path);
            let args = vec!["-sV", "-O", "-sC", "--open", "-oX", "-", "-T4", &tgt];
            let output = tools::sudo_cmd("nmap").args(&args)
                .stdin(std::process::Stdio::inherit())
                .output().expect("Failed to run nmap");
            let xml_str = String::from_utf8_lossy(&output.stdout);
            if !xml_str.is_empty() {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64();
                let summary = context::parse_nmap_xml(&xml_str, &conn, now);
                conn.execute("INSERT INTO nmap_scans (target, scan_time, raw_xml, summary) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![tgt, now, xml_str.to_string(), summary.clone()]).unwrap();
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
        Commands::Report { db, model } => run_report(&db, resolve_model(model.as_deref(), &config)),
        Commands::Ask { db, question, model } => run_ask(&db, &question, resolve_model(model.as_deref(), &config)),
        Commands::Search { db, query } => search::run_search(&db, query.as_deref()),
    }
}
