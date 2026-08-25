# hx_netkit

A Go workspace for network intelligence tooling. Offline-first by design.

## Tools

| Tool | Description |
|------|-------------|
| [correlator](cmd/correlator/) | Scan, capture, and interrogate your network with (optional!) local AI |

## Quick Start

```bash
# Build
go build -o correlator ./cmd/correlator

# Capture packets + nmap scan in parallel
./correlator capture -i en1 -t 192.168.1.0/24 --duration 300

# Run behavioral analysis — no AI required
./correlator analyze -d ~/.correlator/captures/capture_1700000000.db

# Chat with a local AI about the capture
./correlator chat -d ~/.correlator/captures/capture_1700000000.db

# One-shot question
./correlator ask -d capture.db -q "Which devices are suspicious?"
```

## Requirements

- Go 1.25+ to build; no cgo (pure-Go SQLite via modernc.org/sqlite)
- TShark (Wireshark CLI) — packet capture
- Nmap — host/port discovery
- Ollama — local AI inference (`qwen3:4b` or similar); optional
- SQLite — bundled, no separate install

## Design principles

1. **Offline-first.** Every command works with zero internet access. AI runs
   against a local Ollama daemon. Nothing phones home, ever.
2. **Opt-in internet.** The AI can use `websearch` / `webfetch` tools only if
   you allow it: set `[web] enabled = true` in config or pass `--allow-web`.
   Local/private addresses are always blocked for fetches.
3. **Consent-gated tools.** In chat, every tool call the model makes is shown
   and requires approval (`y` / `a` = always / `n`), unless `--yes` is passed.
4. **Readable storage.** Captures are plain SQLite files — query them directly.

## Commands

```
capture         Capture packets + nmap scan in parallel, store metadata
live-interpret  Real-time packet interpretation — no AI needed
chat            Chat with local AI about captured network data
analyze         Run behavioral detectors on a capture — no AI required
ask             Ask the local AI a single question about a capture
report          Generate an AI network security report from a capture
scan            Run nmap only and save results
search          Search network data — natural-language-ish queries, no AI
query           Raw SQL over captures (read-only enforced)
stats/dns/devices/top-talkers   Quick views (--json supported)
list            List saved captures
version         Print version
```

## Architecture

```
cmd/correlator            entry point
internal/
  cli/                    command wiring, prompts
  config/                 TOML configuration, model resolution
  tshark/                 TShark ek JSON parsing + argv building
  nmap/                   XML parsing, stealth levels, OS guessing
  store/                  SQLite schema + persistence (v1-compatible)
  intel/                  per-IP profiles, 18 behavioral detectors,
                          narratives, correlation engine, realtime window
  belief/                 Bayesian BOT/IOT/CAM/CLEAN/UNK tracker
  context/                grounded summary builder for the AI layer
  nlsearch/               non-AI search engine (pure functions + REPL)
  tools/                  validated AI tool surface (12+ tools)
  llm/                    Ollama streaming client, chat loop, background scanner
  live/                   real-time classification engine
  websearch/              opt-in internet access (DDG/SearXNG/Brave/Tavily),
                          hardened against redirect SSRF and DNS rebinding
  textutil/               shared rune-safe text helpers
  devtools/smoketest      synthetic capture generator (dev only)
  version/                build metadata
```

Each package has its own tests; run `go test ./...`.

### The intelligence pipeline

1. **Capture** runs TShark (`-T ek`) and nmap concurrently, writing packets and
   devices into SQLite.
2. **Intel** builds a per-IP profile (25+ metrics: entropy, burst score, port
   diversity, DNS behavior...) and feeds it through 18 detectors — C2 beacon,
   data exfiltration, lateral movement, scanning/recon, Tor/VPN, DGA-like DNS,
   plus benign classifiers (server, browser, gaming, streaming, IoT...).
3. **Belief** maintains a Bayesian distribution per IP and auto-scans the most
   uncertain hosts in the background while you chat.
4. **Context** compiles everything into a grounded brief for the LLM, so the
   model answers from evidence, not imagination.

### Behavioral detectors (18)

BROWSER · BOT · SERVER · IOT · DNS_PROFILER · BEACON · SCANNER · STREAMING ·
CLOUD_SYNC · VPN · TOR · GAME · IOT_COORD · LATERAL_MOVEMENT · DATA_EXFIL ·
C2_BEACON · NET_RECON · PRINTER_IOT

All thresholds are named constants in [`internal/intel/constants.go`](internal/intel/constants.go).

## Configuration

Create `correlator.toml` (cwd) or `~/.correlator/config.toml`:

```toml
interface = "en1"
target    = "192.168.1.0/24"
duration  = 300
model     = "qwen3:4b"        # top-level override wins over [ai].model
num_ctx   = 12288              # Ollama context window (2048..32768)
ollama_url = "http://localhost:11434"
corporate_mode = false         # hides game/streaming/cloud-sync detectors

[ai]
model   = "qwen3:4b"
enabled = true

[web]                          # OFFLINE BY DEFAULT — enable explicitly
enabled      = false
provider     = "duckduckgo"    # duckduckgo | searxng | brave | tavily
# searxng_url      = "http://localhost:8888"
# brave_api_key   = "..."
# tavily_api_key  = "..."
```

## Data storage

Captures land in `~/.correlator/captures/capture_<unix>.db`. Tables:
`packets`, `devices`, `nmap_scans`, `interpretations`. Databases produced by
the v1 Rust release read perfectly — just point `-d` at them.

## License

No.
