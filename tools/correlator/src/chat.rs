use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::config::load_config;
use crate::correlate::OllamaClient;
use crate::db::open_db;
use crate::scanner::{self, BeliefSystem, ScannerEvent, start_scanner};
use crate::context::{build_network_context, format_context_for_ai};
use crate::tools::{ToolCall, ask_permission, execute_tool_call};
use crate::search::search_execute;
use super::BELIEFS;

pub fn run_chat(db_path: &Path, model: &str, live_mode: bool) {
    println!("\n═══════ NETWORK INTELLIGENCE ═══════");

    let ollama = OllamaClient::new(model);
    let config = load_config();
    let ollama_url = config
        .ollama_url
        .as_deref()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or("http://localhost:11434");
    println!("[System] Ollama: {}  model: {}  ctx: {}", ollama_url, model, config.num_ctx);
    if !ollama.is_available() {
        println!("[System] Ollama not available at {}. Entering search mode.", ollama_url);
        println!("[System] Use / prefix for search commands: /ip, /port, /dns, /find, /devices, /stats, /help\n");
        crate::search::run_search(db_path, None);
        return;
    }

    println!("[System] Building context from {}", db_path.display());
    let ctx = build_network_context(db_path);
    let context_str = format_context_for_ai(&ctx);

    let beliefs = Arc::new(Mutex::new(BeliefSystem::new()));
    {
        let mut sys = beliefs.lock().unwrap();
        sys.initialize_from_findings(&ctx.findings);
        for ip in ctx.profiles.keys() {
            sys.ensure_ip(ip);
        }
    }
    let _ = BELIEFS.set(beliefs.clone());

    let scanner_beliefs = beliefs.clone();
    let (scanner_tx, scanner_rx) = std::sync::mpsc::channel::<ScannerEvent>();
    let _scanner_thread = start_scanner(scanner_beliefs, scanner_tx, config.interface.clone());

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
        "LIVE CAPTURE — packets are arriving now. You already have a network summary in context.\n\
         Answer overview questions from that summary first (devices, findings, top talkers).\n\
         Use tools only when you need live/fresh data: sql, search, scan_ip, get_beliefs, nmap, tshark, websearch, webfetch.\n\
         scan_ip takes a single IP (never a CIDR). Be brief."
    } else {
        "You are a network analyst. A capture summary is already in context (devices, stats, top talkers, findings).\n\
         For questions like \"what's happening on the network?\" or \"which are bots?\", answer from the summary first.\n\
         Use tools only when the summary is insufficient: sql, search, scan_ip (single IP only), get_beliefs, nmap, tshark, websearch, webfetch.\n\
         Never tell the user to run commands. Be brief and concrete."
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

    messages.push(json!({
        "role": "system",
        "content": system_prompt
    }));

    messages.push(json!({
        "role": "user",
        "content": format!("Loaded {} devices, {} packets, {} findings.\n\n{}{}",
            ctx.devices.len(), ctx.packet_count, ctx.findings.len(), context_str, belief_context)
    }));
    messages.push(json!({
        "role": "assistant",
        "content": "Got it. I can see your network and I'm tracking beliefs. What do you want to know?"
    }));

    let tools = tool_definitions();

    loop {
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

        messages.push(json!({"role": "user", "content": question}));

        print!("  [thinking…] ");
        io::stdout().flush().ok();

        let response = match ollama.chat(&messages, &tools) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("\n[Error] {}", e);
                println!("  [AI unavailable — try /help or 'quit']");
                messages.pop();
                continue;
            }
        };

        let content = response["content"].as_str().unwrap_or("").to_string();
        let tool_calls = response["tool_calls"].as_array().cloned().unwrap_or_default();

        if tool_calls.is_empty() {
            messages.push(json!({"role": "assistant", "content": content}));
            println!();
            continue;
        }

        messages.push(json!({"role": "assistant", "content": content, "tool_calls": tool_calls}));

        for tc in &tool_calls {
            let name = tc["function"]["name"].as_str().unwrap_or("");
            let args = tc["function"]["arguments"].clone();
            let args_str = format!("{}", args);

            let call = ToolCall {
                name: name.to_string(),
                description: args_str.clone(),
                args: tc.clone(),
            };

            if ask_permission(&call) {
                let tool_result = execute_tool_call(&call, &conn, db_path);
                println!("  [Tool: {}] {}", tool_result.tool_name, tool_result.summary);

                let formatted = format!("[OK] {}: {}\n{}",
                    tool_result.tool_name, tool_result.summary, tool_result.output);
                messages.push(json!({
                    "role": "tool",
                    "tool_name": name,
                    "content": formatted,
                }));
            } else {
                println!("  [Tool denied]");
                let denied = format!("[DENIED] User denied {}: {}", name, call.description);
                messages.push(json!({
                    "role": "tool",
                    "tool_name": name,
                    "content": denied,
                }));
            }
        }

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

fn tool_definitions() -> Vec<Value> {
    vec![
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
    ]
}
