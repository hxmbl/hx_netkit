use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::params;

use crate::db::{init_db, default_db_path};
use crate::tools::sudo_cmd;
use crate::tshark::{extract_fields, tshark_args};

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
        if ip_dst.starts_with("224.") || ip_dst.starts_with("239.") || ip_dst == "255.255.255.255" {
            return;
        }
        if ip_src.starts_with("224.") || ip_src.starts_with("239.") {
            return;
        }

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

            if !role.dns_queries.is_empty() {
                let unique_dns: Vec<String> = role.dns_queries.iter().cloned().collect::<std::collections::HashSet<_>>().into_iter().collect();
                desc.push_str(&format!(" | dns: {}", unique_dns.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
            }

            desc.push_str(&format!(" | {} pkts", role.packet_count));

            interpretations.push((ip.to_string(), desc));
        }

        interpretations
    }
}

pub fn run_live_interpret(interface: &str, duration: u64, no_save: bool, output: Option<&Path>, verbose: bool, use_ai: bool, model: &str) {
    println!("═══════ LIVE INTERPRET ═══════");
    println!("[System] Interface: {}", interface);
    println!("[System] Duration: {}s", duration);
    println!("[System] AI: {}", if use_ai { "enabled" } else { "disabled (use --ai to enable)" });
    println!("[System] Press 'q' to stop early\n");

    let db_path = default_db_path(no_save, output);
    let conn = init_db(&db_path);
    let conn = Arc::new(Mutex::new(conn));

    let args = tshark_args(interface, "");

    let mut child = sudo_cmd("tshark").args(&args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
        .spawn().expect("Failed to start tshark — is it installed?");

    let child_pid = child.id();

    let timer_handle = if !use_ai {
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(duration));
            let _ = sudo_cmd("kill").args(["-INT", &child_pid.to_string()]).output();
        });
        Some(handle)
    } else {
        None
    };

    if use_ai {
        let stdout = child.stdout.take().expect("Failed to take tshark stdout");

        let conn_clone = conn.clone();
        let reader_handle = std::thread::spawn(move || {
            use std::io::BufRead;
            let mut engine = InterpretEngine::new();

            let reader = std::io::BufReader::new(stdout);
            for line_result in reader.lines() {
                if let Ok(raw_line) = line_result {
                    if raw_line.trim().is_empty() { continue; }
                    if raw_line.contains("\"index\"") && !raw_line.contains("\"_source\"") { continue; }

                    if let Some(pkt) = extract_fields(&raw_line) {
                        if let (Some(ref src), Some(ref dst)) = (&pkt.ip_src, &pkt.ip_dst) {
                            engine.process_packet(
                                pkt.epoch.unwrap_or(0.0), src, dst,
                                pkt.tcp_src_port.map(|p| p as u16), pkt.tcp_dst_port.map(|p| p as u16),
                                pkt.udp_src_port.map(|p| p as u16), pkt.udp_dst_port.map(|p| p as u16),
                                pkt.dns_query.as_deref(),
                            );
                            let c = conn_clone.lock().unwrap();
                            let _ = c.execute(
                                "INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json, frame_len) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                params![pkt.epoch, pkt.ip_src.as_deref(), pkt.ip_dst.as_deref(), pkt.tcp_src_port.map(|p| p as i32), pkt.tcp_dst_port.map(|p| p as i32), pkt.udp_src_port.map(|p| p as i32), pkt.udp_dst_port.map(|p| p as i32), pkt.dns_query.as_deref(), raw_line.trim(), pkt.frame_len.map(|p| p as i32)]
                            );
                        }
                    }
                }
            }
        });

        crate::chat::run_chat(&db_path, model, true, 0);

        let _ = child.kill();
        let _ = reader_handle.join();
    } else {
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

                        if let Some(pkt) = extract_fields(&raw_line) {
                            packet_count += 1;

                            if let (Some(ref src), Some(ref dst)) = (&pkt.ip_src, &pkt.ip_dst) {
                                engine.process_packet(
                                    pkt.epoch.unwrap_or(0.0), src, dst,
                                    pkt.tcp_src_port.map(|p| p as u16), pkt.tcp_dst_port.map(|p| p as u16),
                                    pkt.udp_src_port.map(|p| p as u16), pkt.udp_dst_port.map(|p| p as u16),
                                    pkt.dns_query.as_deref(),
                                );

                                let c = conn.lock().unwrap();
                                let _ = c.execute(
                                    "INSERT INTO packets (epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json, frame_len) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                    params![pkt.epoch, pkt.ip_src.as_deref(), pkt.ip_dst.as_deref(), pkt.tcp_src_port.map(|p| p as i32), pkt.tcp_dst_port.map(|p| p as i32), pkt.udp_src_port.map(|p| p as i32), pkt.udp_dst_port.map(|p| p as i32), pkt.dns_query.as_deref(), raw_line.trim(), pkt.frame_len.map(|p| p as i32)]
                                );
                                stored_count += 1;
                            }

                            if verbose || packet_count.is_multiple_of(10) {
                                let elapsed = start.elapsed().as_secs_f64();
                                if let Some(ref dns) = pkt.dns_query {
                                    println!("\r\x1b[K  {:.1}s | {} → {} | DNS: {}", elapsed,
                                        pkt.ip_src.as_deref().unwrap_or("?"),
                                        pkt.ip_dst.as_deref().unwrap_or("?"),
                                        dns);
                                } else if let Some(port) = pkt.tcp_dst_port {
                                    let svc = engine.port_map.get(&(port as u16)).unwrap_or(&"?");
                                    println!("\r\x1b[K  {:.1}s | {} → {}:{} ({})", elapsed,
                                        pkt.ip_src.as_deref().unwrap_or("?"),
                                        pkt.ip_dst.as_deref().unwrap_or("?"),
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
