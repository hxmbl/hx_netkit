use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::params;

use crate::constants;
use crate::db::{init_db, default_db_path};
use crate::context::parse_nmap_xml;
use crate::tools::sudo_cmd;
use crate::tshark::{extract_fields, tshark_args};

pub fn run_capture(interface: &str, target: &str, duration: u64, no_save: bool, output: Option<&Path>,
                   fast: bool, no_nmap: bool, no_tshark: bool, debug: bool, stealth_level: u8) {
    let db_path = default_db_path(no_save, output);
    println!("═══════ CAPTURE ═══════");
    println!("[System] Database: {}", db_path.display());
    println!("[System] Stealth level: {} ({})", stealth_level, match stealth_level {
        0 => "full scan — aggressive nmap, background scanner active",
        1 => "light — rate-limited scan, slower background scanner",
        _ => "passive — TShark only, no active scanning",
    });

    let conn = init_db(&db_path);
    let conn = Arc::new(Mutex::new(conn));

    let tshark_child = if !no_tshark {
        println!("[System] Starting TShark on {} for {}s...", interface, duration);
        let args = tshark_args(interface, "");
        let child = sudo_cmd("tshark").args(&args)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
            .spawn().expect("Failed to start tshark");
        Some(child)
    } else {
        None
    };

    if !no_nmap && stealth_level <= constants::STEALTH_LIGHT {
        println!("[System] Starting nmap scan of {}...", target);
        let mut args: Vec<&str> = constants::nmap_flags(stealth_level, fast).to_vec();
        args.push(target);

        let output = sudo_cmd("nmap").args(&args)
            .stdin(std::process::Stdio::inherit())
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

                        if let Some(pkt) = extract_fields(&raw_line) {
                            packet_count += 1;
                            let c = conn.lock().unwrap();
                            let _ = c.execute(
                                "INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json, frame_len) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                params![pkt.epoch, pkt.ip_src, pkt.ip_dst, pkt.tcp_src_port.map(|p| p as i32), pkt.tcp_dst_port.map(|p| p as i32), pkt.udp_src_port.map(|p| p as i32), pkt.udp_dst_port.map(|p| p as i32), pkt.dns_query, raw_line.trim(), pkt.frame_len.map(|p| p as i32)]
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
