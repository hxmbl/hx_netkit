use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

use crate::config::dirs;

pub fn init_db(db_path: &Path) -> Connection {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(db_path).expect("Failed to open SQLite database");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch REAL, ip_src TEXT, ip_dst TEXT,
            tcp_src_port INTEGER, tcp_dst_port INTEGER,
            udp_src_port INTEGER, udp_dst_port INTEGER,
            dns_query TEXT, raw_json TEXT,
            frame_len INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_epoch ON packets(epoch);
        CREATE INDEX IF NOT EXISTS idx_src ON packets(ip_src);
        CREATE INDEX IF NOT EXISTS idx_dst ON packets(ip_dst);
        CREATE INDEX IF NOT EXISTS idx_dns ON packets(dns_query);"
    ).expect("Failed to create tables");
    // Migration: add frame_len to pre-existing databases
    conn.execute("ALTER TABLE packets ADD COLUMN frame_len INTEGER", []).ok();
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            os_guess TEXT,
            ports TEXT,
            first_seen REAL,
            last_seen REAL,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS nmap_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_time REAL,
            raw_xml TEXT,
            summary TEXT
        );

        CREATE TABLE IF NOT EXISTS interpretations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch REAL,
            ip TEXT,
            role TEXT,
            detail TEXT,
            confidence REAL
        );"
    ).expect("Failed to create tables");
    conn
}

pub fn open_db(db_path: &Path) -> Connection {
    if !db_path.exists() {
        eprintln!("[Error] Database not found: {}", db_path.display());
        std::process::exit(1);
    }
    Connection::open(db_path).expect("Failed to open database")
}

pub fn default_db_path(no_save: bool, output: Option<&Path>) -> PathBuf {
    if let Some(p) = output {
        return p.to_path_buf();
    }
    if no_save {
        return std::env::temp_dir().join(format!("correlator_{}.db", chrono_suffix()));
    }
    let dir = dirs();
    std::fs::create_dir_all(&dir).ok();
    dir.join(format!("capture_{}.db", chrono_suffix()))
}

pub fn chrono_suffix() -> String {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().to_string()
}

pub fn upsert_device(conn: &Connection, ip: &str, mac: Option<&str>, hostname: Option<&str>,
                      vendor: Option<&str>, os_guess: Option<&str>, ports: &str, scan_time: f64) {
    conn.execute(
        "INSERT INTO devices (ip, mac, hostname, vendor, os_guess, ports, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT(ip) DO UPDATE SET
            mac = COALESCE(excluded.mac, mac),
            hostname = COALESCE(excluded.hostname, hostname),
            vendor = COALESCE(excluded.vendor, vendor),
            os_guess = COALESCE(excluded.os_guess, os_guess),
            ports = CASE WHEN excluded.ports != '' THEN excluded.ports ELSE ports END,
            last_seen = excluded.last_seen",
        params![ip, mac, hostname, vendor, os_guess, ports, scan_time],
    ).ok();
}
