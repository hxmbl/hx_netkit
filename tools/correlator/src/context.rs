use std::collections::HashMap;
use std::path::Path;

use rusqlite::Connection;

use crate::correlate::{Correlator, Finding, IpProfile, load_from_db, generate_behavioral_summaries, BehavioralSummary};
use crate::db::{init_db, upsert_device};

pub struct NetworkContext {
    pub devices: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, String)>,
    pub findings: Vec<Finding>,
    pub profiles: HashMap<String, IpProfile>,
    pub cross_ref: String,
    pub packet_count: usize,
    pub behavioral_summaries: Vec<BehavioralSummary>,
}

pub fn build_network_context(db_path: &Path) -> NetworkContext {
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
    let behavioral_summaries = generate_behavioral_summaries(&correlator, &devices, &findings);

    eprintln!(" done ({} IPs, {} findings)", correlator.profiles().len(), findings.len());

    NetworkContext {
        devices,
        findings,
        profiles: correlator.profiles().clone(),
        cross_ref,
        packet_count: total as usize,
        behavioral_summaries,
    }
}

pub fn format_context_for_ai(ctx: &NetworkContext) -> String {
    let mut parts = Vec::new();

    let total_dns: usize = ctx.profiles.values().map(|p| p.dns_domains.len()).sum();
    parts.push(format!(
        "## Overview\n{} packets, {} IPs, {} DNS domains, {} findings, {} devices",
        ctx.packet_count, ctx.profiles.len(), total_dns, ctx.findings.len(), ctx.devices.len(),
    ));

    // ── Behavioral Narratives — the core intelligence ──
    if !ctx.behavioral_summaries.is_empty() {
        parts.push(format!(
            "## What Each Device Is Doing\n\
             This is the behavioral analysis. Each device is described by what it's actually doing on the network.\n\n{}",
            ctx.behavioral_summaries.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("\n")
        ));
    }

    // ── Findings with context ──
    if !ctx.findings.is_empty() {
        let mut findings = ctx.findings.clone();
        findings.sort_by(|a, b| {
            b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
        });
        parts.push(format!(
            "## Anomaly Signals\n\
             These are the detector findings. Each is a signal — cross-reference with behavioral narratives above.\n{}",
            findings.iter().take(20).map(|f| {
                let detail = if f.detail.len() > 150 {
                    format!("{}…", &f.detail[..150])
                } else {
                    f.detail.clone()
                };
                format!("  {} [{}] {}%: {}", f.ip, f.kind, (f.confidence * 100.0) as u32, detail)
            }).collect::<Vec<_>>().join("\n")
        ));
    }

    // ── Top Talkers with richer detail ──
    let mut profiles: Vec<_> = ctx.profiles.values().collect();
    profiles.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    if !profiles.is_empty() {
        parts.push(format!(
            "## Top Talkers (raw stats)\n{}",
            profiles.iter().take(15).map(|p| {
                let duration = p.last_seen - p.first_seen;
                let pps = if duration > 0.0 { p.packet_count as f64 / duration } else { 0.0 };
                let domains = if p.dns_domains.is_empty() { String::new() } else {
                    let mut d: Vec<_> = p.dns_domains.iter().collect();
                    d.sort_by(|a, b| b.1.cmp(a.1));
                    format!(", top domains: {}", d.iter().take(3).map(|(d, c)| format!("{}({})", d, c)).collect::<Vec<_>>().join(", "))
                };
                let ports = if p.dest_ports.is_empty() { String::new() } else {
                    let mut pp: Vec<_> = p.dest_ports.iter().collect();
                    pp.sort_by(|a, b| b.1.cmp(a.1));
                    format!(", top ports: {}", pp.iter().take(3).map(|(p, c)| format!("{}/{}", p, c)).collect::<Vec<_>>().join(", "))
                };
                format!("  {}: {} pkts ({}↑ {}↓, {:.1}s, {:.1} pps){}{}",
                    p.ip, p.packet_count, p.outbound_count, p.inbound_count, duration, pps, domains, ports)
            }).collect::<Vec<_>>().join("\n")
        ));
    }

    // ── Cross-Reference Analysis ──
    if !ctx.cross_ref.is_empty() {
        parts.push(format!(
            "## Cross-Reference (nmap ↔ traffic)\n\
             Matches devices discovered by nmap with their traffic behavior.\n{}",
            ctx.cross_ref
        ));
    }

    parts.join("\n\n")
}

pub fn parse_nmap_xml(xml: &str, conn: &Connection, scan_time: f64) -> String {
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
