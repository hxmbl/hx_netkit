// Package store owns the SQLite capture schema and all persistence helpers.
// Schema is backward compatible with v1.0.0 Rust captures.
package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/hxmbl/hx_netkit/internal/config"
)

// DB wraps a sql.DB handle with correlator-specific helpers.
type DB struct {
	*sql.DB
	mu chan struct{} // write semaphore; modernc sqlite prefers serialized writes
}

func newDB(handle *sql.DB) *DB {
	return &DB{DB: handle, mu: make(chan struct{}, 1)}
}

// Open initializes a database file, creating the schema if needed.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		os.MkdirAll(dir, 0o755)
	}
	handle, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	handle.SetMaxOpenConns(1)
	d := newDB(handle)
	if err := d.initSchema(); err != nil {
		handle.Close()
		return nil, err
	}
	return d, nil
}

// OpenMemory creates an in-memory database (tests, throwaway parsing).
func OpenMemory() (*DB, error) {
	handle, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	handle.SetMaxOpenConns(1)
	d := newDB(handle)
	if err := d.initSchema(); err != nil {
		handle.Close()
		return nil, err
	}
	return d, nil
}

// OpenExisting opens a capture for reading, verifying it is a SQLite file
// with the correlator schema before any command starts using it.
func OpenExisting(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("database not found: %s", path)
	}
	handle, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	handle.SetMaxOpenConns(1)

	var found int
	qerr := handle.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('packets','devices')`,
	).Scan(&found)
	if qerr != nil {
		handle.Close()
		return nil, fmt.Errorf("%s is not a valid SQLite database (%v)", path, qerr)
	}
	if found < 2 {
		handle.Close()
		return nil, fmt.Errorf("%s exists but is not a correlator capture (missing packets/devices tables)", path)
	}
	return newDB(handle), nil
}

// dsn builds a properly URI-escaped DSN so filenames containing '?', '#',
// '%' or spaces cannot corrupt the pragma string.
func dsn(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	return u.String() + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
}

const schema = `
CREATE TABLE IF NOT EXISTS packets (
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
CREATE INDEX IF NOT EXISTS idx_dns ON packets(dns_query);
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
);
`

func (d *DB) initSchema() error {
	_, err := d.Exec(schema)
	return err
}

// Close releases the handle.
func (d *DB) Close() error { return d.DB.Close() }

// Lock acquires the write slot.
func (d *DB) Lock() { d.mu <- struct{}{} }

// Unlock releases the write slot.
func (d *DB) Unlock() { <-d.mu }

// InsertPacket stores one packet row. The epoch is always written as-is
// (never NULL) so downstream readers can ORDER BY and scan it directly;
// zero-value ports/strings are stored as NULL, mirroring the v1 schema.
func (d *DB) InsertPacket(epoch float64, src, dst string, tsrc, tdst, usrc, udst int64, dnsQuery, rawJSON string, frameLen int64) error {
	d.Lock()
	defer d.Unlock()
	_, err := d.Exec(`INSERT INTO packets
		(epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, dns_query, raw_json, frame_len)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		epoch, nzStr(src), nzStr(dst), nullInt(tsrc), nullInt(tdst), nullInt(usrc), nullInt(udst),
		nzStr(dnsQuery), nzStr(rawJSON), nullInt(frameLen))
	return err
}

func nzStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// UpsertDevice inserts or merges device info; non-empty new values win.
func (d *DB) UpsertDevice(ip, mac, hostname, vendor, osGuess, ports string, scanTime float64) error {
	d.Lock()
	defer d.Unlock()
	_, err := d.Exec(`INSERT INTO devices (ip, mac, hostname, vendor, os_guess, ports, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			mac = COALESCE(excluded.mac, mac),
			hostname = COALESCE(excluded.hostname, hostname),
			vendor = COALESCE(excluded.vendor, vendor),
			os_guess = COALESCE(excluded.os_guess, os_guess),
			ports = CASE WHEN excluded.ports != '' THEN excluded.ports ELSE ports END,
			last_seen = excluded.last_seen`,
		ip, nzStr(mac), nzStr(hostname), nzStr(vendor), nzStr(osGuess), ports, scanTime, scanTime)
	return err
}

// RecordScan stores raw nmap XML with its summary.
func (d *DB) RecordScan(target, rawXML, summary string, scanTime float64) error {
	d.Lock()
	defer d.Unlock()
	_, err := d.Exec(`INSERT INTO nmap_scans (target, scan_time, raw_xml, summary) VALUES (?, ?, ?, ?)`,
		target, scanTime, rawXML, summary)
	return err
}

// DeviceRow is a row from the devices table.
type DeviceRow struct {
	IP       string  `json:"ip"`
	MAC      *string `json:"mac,omitempty"`
	Hostname *string `json:"hostname,omitempty"`
	Vendor   *string `json:"vendor,omitempty"`
	OSGuess  *string `json:"os_guess,omitempty"`
	Ports    string  `json:"ports"`
}

// Devices lists known devices ordered by IP.
func (d *DB) Devices() ([]DeviceRow, error) {
	rows, err := d.Query(`SELECT ip, mac, hostname, vendor, os_guess, ports FROM devices ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceRow
	for rows.Next() {
		var r DeviceRow
		if err := rows.Scan(&r.IP, &r.MAC, &r.Hostname, &r.Vendor, &r.OSGuess, &r.Ports); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Stats summarizes a capture.
type Stats struct {
	Packets    uint64 `json:"packets"`
	Devices    uint64 `json:"devices"`
	DNSDomains uint64 `json:"dns_domains"`
	NmapScans  uint64 `json:"nmap_scans"`
}

// Stats computes table counts for the capture.
func (d *DB) Stats() (Stats, error) {
	var s Stats
	if err := d.QueryRow(`SELECT COUNT(*) FROM packets`).Scan(&s.Packets); err != nil && err != sql.ErrNoRows {
		return s, err
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&s.Devices); err != nil && err != sql.ErrNoRows {
		return s, err
	}
	if err := d.QueryRow(`SELECT COUNT(DISTINCT dns_query) FROM packets WHERE dns_query IS NOT NULL`).Scan(&s.DNSDomains); err != nil && err != sql.ErrNoRows {
		return s, err
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM nmap_scans`).Scan(&s.NmapScans); err != nil && err != sql.ErrNoRows {
		return s, err
	}
	return s, nil
}

// DNSRow aggregates DNS queries by requester.
type DNSRow struct {
	Query string `json:"query"`
	Src   string `json:"src"`
	Count uint64 `json:"count"`
}

// DNSQueries returns distinct queries with their dominant requester.
// Grouping by (query, src) and keeping the top pair per query makes the
// attribution deterministic — a bare GROUP BY would let SQLite pick an
// arbitrary requester for each domain.
func (d *DB) DNSQueries() ([]DNSRow, error) {
	rows, err := d.Query(`SELECT dns_query, COALESCE(ip_src,''), cnt FROM (
			SELECT dns_query, ip_src, COUNT(*) AS cnt,
				ROW_NUMBER() OVER (
					PARTITION BY dns_query
					ORDER BY COUNT(*) DESC, COALESCE(ip_src,'') ASC
				) AS rn
			FROM packets WHERE dns_query IS NOT NULL
			GROUP BY dns_query, ip_src
		) WHERE rn = 1 ORDER BY cnt DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSRow
	for rows.Next() {
		var r DNSRow
		if err := rows.Scan(&r.Query, &r.Src, &r.Count); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TalkerRow pairs an IP with its packet count.
type TalkerRow struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

// TopTalkers ranks source IPs by packet volume.
func (d *DB) TopTalkers(limit int) ([]TalkerRow, error) {
	rows, err := d.Query(`SELECT COALESCE(ip_src,''), COUNT(*) AS cnt
		FROM packets GROUP BY ip_src ORDER BY cnt DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TalkerRow
	for rows.Next() {
		var r TalkerRow
		if err := rows.Scan(&r.IP, &r.Count); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NmapSummary returns stored scan summaries (newest first).
func (d *DB) NmapSummaries() ([]string, error) {
	rows, err := d.Query(`SELECT summary FROM nmap_scans ORDER BY scan_time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			continue
		}
		if strings.TrimSpace(s.String) != "" {
			out = append(out, s.String)
		}
	}
	return out, rows.Err()
}

// CapturePath builds the default save path for a new capture. Nanosecond
// timestamps keep same-second captures from colliding on one file.
func CapturePath(noSave bool, output string) string {
	if output != "" {
		return output
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	var dir string
	if noSave {
		dir = os.TempDir()
	} else {
		dir = config.CapturesDir()
		os.MkdirAll(dir, 0o755)
	}
	name := "capture_" + suffix + ".db"
	if noSave {
		name = "correlator_" + suffix + ".db"
	}
	return filepath.Join(dir, name)
}

// UpdateLatestSymlink points ~/.correlator/captures/latest.db at path so
// flag-less commands (chat, analyze, …) pick the newest capture. Silently
// no-ops when path lives outside the captures directory.
func UpdateLatestSymlink(path string) {
	dir := config.CapturesDir()
	absPath, err := filepath.Abs(path)
	if err != nil {
		return
	}
	absDir, err := filepath.Abs(dir)
	if err != nil || !strings.HasPrefix(absPath, absDir+string(filepath.Separator)) {
		return
	}
	link := filepath.Join(dir, "latest.db")
	os.Remove(link)
	_ = os.Symlink(absPath, link)
}

// QueryRows executes arbitrary SQL and renders results as columns + rows of
// strings. Only used by the query command / sql tool after validation.
func (d *DB) QueryRows(sqlText string, limit int) (cols []string, rows [][]string, err error) {
	stmt, err := d.Prepare(sqlText)
	if err != nil {
		return nil, nil, err
	}
	defer stmt.Close()

	rs, err := stmt.Query()
	if err != nil {
		return nil, nil, err
	}
	defer rs.Close()

	colTypes, err := rs.ColumnTypes()
	if err != nil {
		return nil, nil, err
	}
	cols = make([]string, len(colTypes))
	for i, ct := range colTypes {
		cols[i] = ct.Name()
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rs.Next() {
		if err := rs.Scan(ptrs...); err != nil {
			return cols, nil, err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			switch tv := v.(type) {
			case nil:
				row[i] = "NULL"
			case []byte:
				row[i] = string(tv)
			case string:
				row[i] = tv
			default:
				row[i] = fmt.Sprintf("%v", tv)
			}
		}
		rows = append(rows, row)
		if limit > 0 && len(rows) >= limit {
			break
		}
	}
	return cols, rows, rs.Err()
}
