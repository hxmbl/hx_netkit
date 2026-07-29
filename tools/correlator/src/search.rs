use std::io::{self, Write};
use std::path::Path;

use rusqlite::{Connection, params};

use crate::db::open_db;

pub fn run_search(db_path: &Path, initial_query: Option<&str>) {
    let conn = open_db(db_path);
    println!("\n═══════ NETWORK SEARCH ENGINE ═══════");
    println!("[System] Database: {}", db_path.display());
    println!("[System] Commands: ip <addr>, port <num>, dns <domain>, find <text>, devices, stats, help, quit\n");

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

pub fn search_execute(conn: &Connection, query: &str) {
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

            let mut stmt = conn.prepare(
                "SELECT ip_dst, COUNT(*) as cnt FROM packets WHERE ip_src LIKE ?1 GROUP BY ip_dst ORDER BY cnt DESC LIMIT 20"
            ).unwrap();
            let rows = stmt.query_map(params![pattern], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            println!("{} connects to:", arg);
            for row in rows {
                let (ip, count): (String, u64) = row.unwrap();
                println!("  → {} (×{})", ip, count);
            }

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
