use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde_json::{json, Value};

use crate::config::load_config;
use crate::tshark::{extract_fields, tshark_args};
use crate::scanner;

use super::BELIEFS;

static ALWAYS_ALLOW: AtomicBool = AtomicBool::new(false);

pub struct ToolCall {
    pub name: String,
    pub description: String,
    pub args: Value,
}

pub struct ToolResult {
    pub tool_name: String,
    pub summary: String,
    pub output: String,
}

pub fn sudo_cmd(prog: &str) -> Command {
    let is_root = Command::new("id").arg("-u").output()
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

pub fn ask_permission(call: &ToolCall) -> bool {
    if ALWAYS_ALLOW.load(Ordering::Relaxed) {
        return true;
    }
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

pub fn execute_tool_call(call: &ToolCall, conn: &Connection, db_path: &Path) -> ToolResult {
    if let Some(result) = try_exec_tool(&call.args, conn, db_path) {
        return result;
    }

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

fn parse_tool_arguments(args: &Value) -> Value {
    match args {
        Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
        other => other.clone(),
    }
}

pub fn try_exec_tool(val: &Value, conn: &Connection, db_path: &Path) -> Option<ToolResult> {
    if let Some(func) = val.get("function") {
        let tool = func.get("name").and_then(|t| t.as_str())?;
        let args = parse_tool_arguments(func.get("arguments").unwrap_or(&json!({})));
        return try_exec_tool_named(tool, &args, conn, db_path);
    }
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

// ── Input Validation ──

pub fn is_valid_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 64 { return false; }
    if target.contains('/') { return false; }
    target.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ',' || c == '-' || c == ' ')
}

fn is_valid_bpf(filter: &str) -> bool {
    if filter.is_empty() { return true; }
    if filter.len() > 256 { return false; }
    let dangerous = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '"', '\''];
    !filter.chars().any(|c| dangerous.contains(&c))
}

pub fn is_safe_sql(query: &str) -> bool {
    let upper = query.trim().to_uppercase();
    // Block dangerous keywords but allow UNION in SELECT context
    let blocked = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE", "EXEC", "EXECUTE", "INTO", "LOAD", "INFILE", "OUTFILE"];
    for kw in blocked {
        if upper.contains(kw) {
            return false;
        }
    }
    upper.starts_with("SELECT") || upper.starts_with("WITH") ||
    upper.starts_with("SHOW") || upper.starts_with("EXPLAIN")
}

fn is_safe_search(query: &str) -> bool {
    if query.is_empty() || query.len() > 128 { return false; }
    let dangerous = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r'];
    !query.chars().any(|c| dangerous.contains(&c))
}

// ── Tool Implementations ──

pub fn run_tool_nmap(target: &str) -> ToolResult {
    println!("\n  [Tool] Running nmap on {}...", target);
    let args = vec!["-sn", "-T5", "--max-retries", "1", "--host-timeout", "5s", target];
    let output = sudo_cmd("nmap").args(&args)
        .output().expect("Failed to run nmap");
    let xml = String::from_utf8_lossy(&output.stdout);

    let conn = Connection::open(":memory:").unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    let summary = crate::context::parse_nmap_xml(&xml, &conn, now);

    let device_count: u64 = conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0);

    ToolResult {
        tool_name: "nmap".into(),
        summary: format!("Found {} devices on {}", device_count, target),
        output: summary,
    }
}

pub fn run_tool_tshark(filter: &str, duration: u64, _db_path: &Path) -> ToolResult {
    let iface = load_config().interface;
    println!("\n  [Tool] Capturing traffic for {}s (interface: {}, filter: {})...", duration, iface, filter);
    let args = tshark_args(&iface, filter);

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
            if let Some(pkt) = extract_fields(&line) {
                let dst = pkt.ip_dst.unwrap_or_default();
                let dns = pkt.dns_query.map(|d| format!(" [{}]", d)).unwrap_or_default();
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

pub fn run_tool_sql(query: &str, conn: &Connection) -> ToolResult {
    println!("\n  [Tool] Running SQL: {}", query);

    let semicolon_count = query.chars().filter(|&c| c == ';').count();
    if semicolon_count > 1 {
        return ToolResult {
            tool_name: "sql".into(),
            summary: "Rejected multi-statement query".into(),
            output: "Only single SELECT queries are allowed.".into(),
        };
    }

    // Additional safety: block dangerous keywords even in SELECT
    let upper = query.to_uppercase();
    let blocked = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE", "EXEC", "EXECUTE", "INTO", "LOAD", "INFILE", "OUTFILE"];
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

pub fn run_tool_search(query: &str, conn: &Connection) -> ToolResult {
    println!("\n  [Tool] Searching: {}", query);
    let mut output = Vec::new();
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

pub fn run_tool_webfetch(url: &str) -> ToolResult {
    println!("\n  [Tool] Fetching {}...", url);
    match reqwest::blocking::get(url) {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
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

pub fn run_tool_websearch(query: &str) -> ToolResult {
    println!("\n  [Tool] Searching web: {}...", query);
    let search_url = format!("https://lite.duckduckgo.com/lite/?q={}", urlencoding::encode(query));
    match reqwest::blocking::get(&search_url) {
        Ok(resp) => {
            let html = resp.text().unwrap_or_default();
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

pub fn run_tool_scan_ip(target: &str) -> ToolResult {
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
        output: format!("IP: {}\nStatus: {}\nOS: {}\n{}", target, status, os_hint, ports_str),
    }
}

pub fn run_tool_get_beliefs(target: Option<&str>) -> ToolResult {
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

fn extract_search_results(html: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut in_result = false;
    let mut current_title = String::new();
    let mut current_url = String::new();
    let mut current_snippet = String::new();

    for line in html.lines() {
        let trimmed = line.trim();
        if trimmed.contains("result__a") || trimmed.contains("result-link") {
            if let Some(href_start) = trimmed.find("href=\"") {
                let rest = &trimmed[href_start + 6..];
                if let Some(href_end) = rest.find('"') {
                    current_url = rest[..href_end].to_string();
                    in_result = true;
                }
            }
            if let Some(text_start) = trimmed.find('>') {
                let text = &trimmed[text_start + 1..];
                if let Some(text_end) = text.find('<') {
                    current_title = text[..text_end].trim().to_string();
                }
            }
        }
        if in_result && (trimmed.contains("result__snippet") || trimmed.contains("result-snippet")) {
            if let Some(text_start) = trimmed.find('>') {
                let text = &trimmed[text_start + 1..];
                if let Some(text_end) = text.find('<') {
                    current_snippet = text[..text_end].trim().to_string();
                }
            }
        }
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

    if in_result && !current_title.is_empty() {
        results.push(format!("{} {}\n{}", current_title, current_url, current_snippet));
    }

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
