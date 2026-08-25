# Changes

## v2.1.0 — UX release

Four-phase usability overhaul.

**First run & diagnostics**
- `correlator doctor`: verifies tshark/nmap, lists capture-capable
  interfaces with addresses, checks Ollama reachability and whether the
  configured model is pulled, disk space, privileges — every failure
  carries a fix-it hint.
- `correlator init`: interactive wizard that detects your interface,
  derives the scan CIDR, and writes a commented correlator.toml.
- Captures now update a `latest.db` symlink, so `analyze` / `chat` /
  `ask` work with no `-d` flag; capture completion prints next steps.
- Root help gained worked examples; shell completions advertised.

**Output polish**
- Severity-coded findings (critical=red, warning=amber, benign=blue)
  with confidence bars; auto-disabled when piped (`NO_COLOR` respected).
- `analyze --min-confidence N --top N --kind threat|benign|SCANNER,…`
  plus `--json`.
- Live capture progress meter: packet count, MB, packets/sec, elapsed
  vs remaining.
- Ctrl-C during capture stops tshark gracefully — partial captures are
  finalized and summarized instead of lost.

**Interactive REPL**
- readline-backed chat/search: arrow-key history (~/.correlator/),
  tab completion over slash commands and discovered device IPs.
- Ctrl-C cancels the current line; Ctrl-D quits.
- `/help` now shows session help (it previously leaked search help).

**One-command flow**
- `correlator run`: doctor gate → interface/target/duration prompts →
  capture → styled findings → optional AI chat hand-off.
- `correlator captures list|info|prune` — dates, sizes, packet counts;
  prune supports --keep/--older-than/--yes with a dry-run preview.

## v2.0.1

Hardening release — fixes from a full security and quality audit.

- chat: seeded network context is no longer discarded; the model answers
  from capture evidence as intended.
- chat: single shared stdin reader between the chat loop and tool
  permission prompts — keystrokes can no longer be swallowed mid-session.
- captures: `chat`/`ask` default-database selection sorts numerically
  (capture_100 beats capture_99); new captures use nanosecond names so
  same-second runs never collide; `list` orders the same way.
- webfetch: hardened HTTP path — every redirect hop is screened against
  private/loopback ranges and hostnames resolve through a guard that
  blocks internal IPs (defeats redirect SSRF and DNS rebinding).
  User-configured search endpoints (self-hosted SearXNG on the LAN) keep
  using a plain client; missing provider credentials now warn and name
  the active provider in the chat banner.
- report/JSON: detector findings serialize their kind ("C2_BEACON", …)
  plus confidence percent.
- background scanner: Stop() waits at most 2s instead of hanging CLI exit
  behind an in-flight nmap probe.
- ollama: availability probes use a 3s timeout (no more multi-minute
  stalls on unreachable hosts); auto-started daemon output no longer
  pollutes the terminal.
- store: epoch is always written (never NULL); OpenExisting rejects
  non-SQLite files and foreign schemas with clear errors; DSNs are
  URI-escaped for filenames containing ?/#/%/spaces.
- sql guard: word-boundary keyword matching with literal stripping —
  identifiers like created_at or quoted text no longer trigger false
  rejections while DROP/DELETE/etc. stay blocked.
- tools: explicit duration=0 / limit=0 now mean "default" rather than
  collapsing to the minimum; tshark stderr surfaces in errors.
- live --ai: capture keeps running while you chat (v1 behavior restored),
  with a duration watchdog.
- intel: bounded packet retention (~50k evidence window), IPv6-aware
  private-address checks, deterministic finding order and narratives,
  "hp" printer keyword requires standalone token, realtime window honors
  corporate mode.
- misc: rune-safe truncation everywhere (no more split UTF-8), escaped
  LIKE patterns in search, unknown slash commands print guidance,
  malformed TOML warns instead of silently ignoring.

## v2.0.0

Complete rewrite in Go.

- Single pure-Go binary (no cgo): cross-compiles to Linux/macOS, amd64/arm64.
- Same SQLite schema as v1 — old capture databases keep working.
- Intelligence layer preserved and expanded: 18 behavioral detectors,
  Bayesian belief tracking, narratives, cross-referencing.
- New offline `analyze` command: full detector report without any AI.
- New opt-in web access module for AI tools (`[web]` config or `--allow-web`),
  with pluggable providers (DuckDuckGo Lite default, SearXNG, Brave, Tavily)
  and private-address blocking on `webfetch`.
- Tool calls now validated before execution: read-only single-statement SQL,
  strict IP targets (no CIDR from the model), BPF character filtering.
- Chat gains `/web on|off`, `--yes` auto-approval, and richer context tools
  (network_context, devices, anomalies, threats).
- `--json` output for stats/dns/top-talkers/devices.
- Test suite rewritten and expanded across all packages, including
  httptest-based Ollama and search-provider fakes.

## v1.0.0

Initial release (Rust).
