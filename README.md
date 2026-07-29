# hx_netkit

A Rust workspace for network intelligence tooling.

## Tools

| Tool | Description |
|------|-------------|
| [correlator](tools/correlator/) | Scan, capture, and interrogate network traffic with local AI |

## Quick Start

```bash
# Build everything
cargo build --release

# Run the correlator
./target/release/correlator --help
```

## Requirements

- Rust 2021 edition
- TShark (Wireshark CLI) — for packet capture
- Nmap — for network scanning
- Ollama — for local AI inference (qwen3:4b or similar)
- SQLite — bundled via rusqlite, no separate install needed

## License

Private — internal use only.
