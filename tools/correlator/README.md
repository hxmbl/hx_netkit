# correlator

Network intelligence tool — scan, capture, and interrogate your network with local AI.

No cloud. No telemetry. Everything runs on your machine via Ollama.

## Commands

```bash
# Capture packets + nmap scan in parallel
correlator capture -i en1 -t 192.168.1.0/24 --duration 300

# Capture with stealth (1=light scan, 2=passive, no scanning)
correlator capture -i en1 -t 192.168.1.0/24 --stealth-level 2

# Chat with AI about captured data
correlator chat -d ~/.correlator/captures/latest.db

# Real-time packet interpretation (no AI, just smart TShark)
correlator live-interpret -i en1 --ai

# Ask a single question
correlator ask -d ~/.correlator/captures/latest.db -q "Which devices are suspicious?"

# Search without AI
correlator search -d ~/.correlator/captures/latest.db -q "port 443"

# SQL queries directly
correlator query "SELECT src_ip, COUNT(*) FROM packets GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 10" -d db.sqlite

# Quick views
correlator stats -d db.sqlite
correlator dns -d db.sqlite
correlator top-talkers -d db.sqlite
correlator devices -d db.sqlite

# List saved captures
correlator list
```

## Architecture

The correlator has three layers that work as a **mesh** — each layer can reach the others directly:

```
┌─────────────────────────────────────────────┐
│  AI Layer (chat, ask, report)               │
│  9 tools: sql, nmap, tshark, search,        │
│  network_context, devices, anomalies,        │
│  threats, packets                            │
├─────────────────────────────────────────────┤
│  Intelligence Layer                         │
│  Behavioral analysis, 15 detectors,         │
│  device profiling (25+ metrics),            │
│  Bayesian belief tracking                   │
├─────────────────────────────────────────────┤
│  Capture Layer                              │
│  TShark + nmap, SQLite storage,             │
│  background scanning, stealth modes         │
└─────────────────────────────────────────────┘
```

### Modules

| Module | Lines | Purpose |
|--------|-------|---------|
| `correlator.rs` | ~2500 | Core engine: packet analysis, IP profiling, 15 behavioral detectors, device classification, narratives |
| `tools.rs` | ~740 | 9 AI-callable tools with input validation and sanitization |
| `scanner.rs` | ~500 | Background nmap scanner, OS detection, Bayesian belief system (5 categories) |
| `chat.rs` | ~400 | AI chat loop — builds context, sends to Ollama, parses tool calls |
| `main.rs` | ~390 | CLI definition (clap), subcommand dispatch |
| `live.rs` | ~350 | Real-time packet interpretation engine (no AI needed) |
| `constants.rs` | ~300 | All detection thresholds as named constants |
| `context.rs` | ~280 | Builds network context for AI: narratives, anomalies, top talkers, cross-reference |
| `search.rs` | ~220 | Natural language search REPL |
| `capture.rs` | ~120 | Orchestrates TShark + nmap capture |
| `db.rs` | ~100 | SQLite schema and device upsert |
| `tshark.rs` | ~85 | TSharkPacket struct and field extraction |
| `config.rs` | ~80 | Config loading from TOML, model resolution |

### Behavioral Analysis

The intelligence layer builds a per-IP profile with 25+ metrics:

- Packet counts, byte volumes, duration, packets/sec
- Protocol distribution (TCP/UDP/DNS)
- Destination IP and port diversity
- Session depth and port entropy
- DNS domain diversity and single-label queries
- Burst score and packet size variance
- Internal vs external peer ratios

These feed into **15 behavioral detectors** that produce findings with confidence scores:

| Detector | What it catches |
|----------|----------------|
| C2 Beacon | Regular callback intervals to external hosts |
| Data Exfiltration | Large outbound payloads to single destinations |
| Lateral Movement | Internal host scanning and connections |
| Scanner | Port scanning across multiple hosts |
| Network Recon | DNS enumeration and service discovery |
| Tor Usage | Connections to known Tor infrastructure |
| Bot Behavior | Automated traffic patterns |
| Periodic Beaconing | Regular interval communications |
| DNS Profiling | Extensive DNS enumeration |
| DGA Detection | Single-label domain queries |
| Encrypted Tunnel | Uniform packet sizes on non-standard ports |
| Game/Streaming | Consumer traffic patterns |
| Cloud Sync | Periodic large uploads to cloud providers |
| SMB Activity | Windows file sharing traffic |
| Printer/IoT | Device fingerprinting |

### AI Tools

The AI layer has 9 tools it can invoke during conversation:

| Tool | Description |
|------|-------------|
| `sql` | Query the packet database directly |
| `nmap` | Run nmap scans on discovered hosts |
| `tshark` | Capture filtered packet data |
| `search` | Search network data with natural language |
| `network_context` | Get full behavioral context for an IP |
| `devices` | List all discovered devices |
| `anomalies` | List all behavioral anomalies |
| `threats` | Get threat summary with Bayesian beliefs |
| `packets` | Query raw packet evidence with filters |

The `packets` tool provides direct evidence access — the AI can filter by IP, peer, port, direction, and time range without going through the intelligence layer's summary.

### Stealth Levels

| Level | Nmap Flags | Description |
|-------|-----------|-------------|
| 0 | `-sS -sV -O --top-ports 1000` | Full scan (default) |
| 1 | `-sS --top-ports 100` | Light scan |
| 2 | *(none)* | Passive — no scanning |

## Configuration

Create `correlator.toml` in the project directory or `~/.correlator/config.toml`:

```toml
interface = "en1"
target = "192.168.1.0/24"
duration = 300
model = "qwen3:4b"
num_ctx = 12288

[ai]
model = "qwen3:4b"
enabled = true
```

## Data Storage

Captures are stored in SQLite databases at `~/.correlator/captures/`. The latest capture is symlinked as `latest.db`. Each database contains:

- `packets` — every packet with IPs, ports, protocol, timestamps, DNS queries
- `devices` — discovered hosts with OS, MAC, vendor, open ports
- `nmap_scans` — raw nmap XML output
- `alerts` — security findings

## Dependencies

- `rusqlite` (bundled SQLite)
- `clap` (CLI)
- `reqwest` + `tokio` (Ollama HTTP client)
- `toml` + `serde` (config)
- `crossterm` (terminal UI)
- `urlencoding` (URL-safe encoding)

External: TShark, Nmap, Ollama
