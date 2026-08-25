// Package nlsearch implements the non-AI natural-language-ish query engine
// over capture databases. Every command returns a string so rendering is
// fully testable; the CLI just prints results.
package nlsearch

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/hxmbl/hx_netkit/internal/store"
)

// Help is the command reference shown by `help`.
const Help = `Commands:
  ip <addr>        — find all traffic to/from an IP
  port <num>       — find all traffic on a port
  dns <domain>     — find DNS queries matching domain
  find <text>      — search all fields for text
  devices          — list all known devices
  stats            — show capture statistics
  talkers [n]      — top n talkers (default 20)
  recent [n]       — last n packets (default 20)
  connections <ip> — show who this IP talks to
  services <ip>    — show services on this IP
  help             — this text
  quit / exit      — leave`

// Execute runs one search command against db and returns display output.
func Execute(db *store.DB, query string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return ""
	}
	parts := strings.SplitN(query, " ", 2)
	cmd := strings.ToLower(parts[0])
	arg := ""
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}

	switch cmd {
	case "help", "h", "?":
		return Help
	case "quit", "exit", "q":
		return ""
	case "ip", "host":
		return searchIP(db, arg)
	case "port", "p":
		return searchPort(db, arg)
	case "dns", "d":
		return searchDNS(db, arg)
	case "find", "f", "search", "s":
		return findText(db, arg)
	case "devices":
		return listDevices(db)
	case "stats":
		return statsLine(db)
	case "talkers", "top":
		return topTalkers(db, arg)
	case "recent", "r":
		return recentPackets(db, arg)
	case "connections", "conn":
		return connections(db, arg)
	case "services", "svc":
		return services(db, arg)
	default:
		return fmt.Sprintf("Unknown command: '%s'. Type 'help' for commands.", cmd)
	}
}

// likePattern builds an escaped LIKE pattern so user input containing
// '%' or '_' is matched literally instead of acting as a wildcard.
func likePattern(s string) string {
	var b strings.Builder
	b.WriteByte('%')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '%':
			b.WriteString(`\%`)
		case '_':
			b.WriteString(`\_`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('%')
	return b.String()
}

func searchIP(db *store.DB, arg string) string {
	if arg == "" {
		return "Usage: ip <address>"
	}
	pattern := likePattern(arg)
	rows, err := db.Query(`SELECT epoch, COALESCE(ip_src,''), COALESCE(ip_dst,''),
		COALESCE(tcp_dst_port,0), COALESCE(udp_dst_port,0), COALESCE(dns_query,'')
		FROM packets WHERE ip_src LIKE ? ESCAPE '\' OR ip_dst LIKE ? ESCAPE '\' ORDER BY epoch DESC LIMIT 100`,
		pattern, pattern)
	if err != nil {
		return "Query failed: " + err.Error()
	}
	defer rows.Close()

	var b strings.Builder
	fmt.Fprintf(&b, "Traffic for %s:\n", arg)
	n := 0
	for rows.Next() {
		var epoch sql.NullFloat64
		var src, dst, dns sql.NullString
		var tport, uport sql.NullInt64
		if err := rows.Scan(&epoch, &src, &dst, &tport, &uport, &dns); err != nil {
			continue
		}
		ts := ""
		if epoch.Valid {
			ts = strconv.FormatFloat(epoch.Float64, 'f', 0, 64)
		}
		port := ""
		if tport.Int64 > 0 || uport.Int64 > 0 {
			p := tport.Int64
			if p == 0 {
				p = uport.Int64
			}
			port = fmt.Sprintf(":%d", p)
		}
		dnsStr := ""
		if dns.String != "" {
			dnsStr = " [" + dns.String + "]"
		}
		fmt.Fprintf(&b, "  %s %s → %s%s%s\n", ts, src.String, dst.String, port, dnsStr)
		n++
	}
	if n == 0 {
		b.WriteString("  (no traffic found)\n")
	}
	return b.String()
}

func searchPort(db *store.DB, arg string) string {
	if arg == "" {
		return "Usage: port <number>"
	}
	port, err := strconv.Atoi(arg)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Sprintf("Invalid port: '%s'. Must be 1-65535.", arg)
	}
	rows, err := db.Query(`SELECT epoch, COALESCE(ip_src,''), COALESCE(ip_dst,'') FROM packets
		WHERE tcp_dst_port = ? OR udp_dst_port = ? OR tcp_src_port = ? OR udp_src_port = ?
		ORDER BY epoch DESC LIMIT 100`, port, port, port, port)
	if err != nil {
		return "Query failed: " + err.Error()
	}
	defer rows.Close()

	var b strings.Builder
	fmt.Fprintf(&b, "Traffic on port %d:\n", port)
	n := 0
	for rows.Next() {
		var epoch sql.NullFloat64
		var src, dst sql.NullString
		if err := rows.Scan(&epoch, &src, &dst); err != nil {
			continue
		}
		ts := ""
		if epoch.Valid {
			ts = strconv.FormatFloat(epoch.Float64, 'f', 0, 64)
		}
		fmt.Fprintf(&b, "  %s %s → %s\n", ts, src.String, dst.String)
		n++
	}
	if n == 0 {
		b.WriteString("  (no traffic on this port)\n")
	}
	return b.String()
}

func searchDNS(db *store.DB, arg string) string {
	if arg == "" {
		return "Usage: dns <domain>"
	}
	rows, err := db.Query(`SELECT dns_query, COALESCE(ip_src,''), COUNT(*) AS cnt FROM packets
		WHERE dns_query LIKE ? ESCAPE '\' GROUP BY dns_query ORDER BY cnt DESC LIMIT 50`, likePattern(arg))
	if err != nil {
		return "Query failed: " + err.Error()
	}
	defer rows.Close()

	var b strings.Builder
	fmt.Fprintf(&b, "DNS queries matching '%s':\n", arg)
	n := 0
	for rows.Next() {
		var q, src sql.NullString
		var cnt int
		if err := rows.Scan(&q, &src, &cnt); err != nil {
			continue
		}
		fmt.Fprintf(&b, "  %s → %s (×%d)\n", src.String, q.String, cnt)
		n++
	}
	if n == 0 {
		b.WriteString("  (no DNS matches)\n")
	}
	return b.String()
}

func findText(db *store.DB, arg string) string {
	if arg == "" {
		return "Usage: find <text>"
	}
	pattern := likePattern(arg)
	rows, err := db.Query(`SELECT epoch, COALESCE(ip_src,''), COALESCE(ip_dst,''), COALESCE(dns_query,'')
		FROM packets WHERE raw_json LIKE ? ESCAPE '\' OR dns_query LIKE ? ESCAPE '\' OR ip_src LIKE ? ESCAPE '\' OR ip_dst LIKE ? ESCAPE '\'
		ORDER BY epoch DESC LIMIT 50`, pattern, pattern, pattern, pattern)
	if err != nil {
		return "Query failed: " + err.Error()
	}
	defer rows.Close()

	var b strings.Builder
	fmt.Fprintf(&b, "Results for '%s':\n", arg)
	n := 0
	for rows.Next() {
		var epoch sql.NullFloat64
		var src, dst, dns sql.NullString
		if err := rows.Scan(&epoch, &src, &dst, &dns); err != nil {
			continue
		}
		ts := ""
		if epoch.Valid {
			ts = strconv.FormatFloat(epoch.Float64, 'f', 0, 64)
		}
		dnsStr := ""
		if dns.String != "" {
			dnsStr = " [" + dns.String + "]"
		}
		fmt.Fprintf(&b, "  %s %s → %s%s\n", ts, src.String, dst.String, dnsStr)
		n++
	}
	if n == 0 {
		b.WriteString("  (no matches)\n")
	}
	return b.String()
}

func listDevices(db *store.DB) string {
	devices, err := db.Devices()
	if err != nil {
		return "Query failed: " + err.Error()
	}
	var b strings.Builder
	b.WriteString("Known devices:\n")
	for _, d := range devices {
		host, osG := "", ""
		if d.Hostname != nil {
			host = *d.Hostname
		}
		if d.OSGuess != nil {
			osG = *d.OSGuess
		}
		ports := d.Ports
		if ports == "" {
			ports = "no ports"
		}
		fmt.Fprintf(&b, "  %s (%s) — %s [%s]\n", d.IP, host, osG, ports)
	}
	if len(devices) == 0 {
		b.WriteString("  (no known devices)\n")
	}
	return b.String()
}

func statsLine(db *store.DB) string {
	s, err := db.Stats()
	if err != nil {
		return "Query failed: " + err.Error()
	}
	return fmt.Sprintf("Stats: %d packets, %d devices, %d DNS domains", s.Packets, s.Devices, s.DNSDomains)
}

func topTalkers(db *store.DB, arg string) string {
	limit := 20
	if arg != "" {
		if v, err := strconv.Atoi(arg); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	talkers, err := db.TopTalkers(limit)
	if err != nil {
		return "Query failed: " + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Top %d talkers:\n", limit)
	for _, t := range talkers {
		fmt.Fprintf(&b, "  %s: %d packets\n", t.IP, t.Count)
	}
	if len(talkers) == 0 {
		b.WriteString("  (no data)\n")
	}
	return b.String()
}

func recentPackets(db *store.DB, arg string) string {
	limit := 20
	if arg != "" {
		if v, err := strconv.Atoi(arg); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	rows, err := db.Query(`SELECT epoch, COALESCE(ip_src,''), COALESCE(ip_dst,''),
		COALESCE(tcp_dst_port,0), COALESCE(dns_query,'')
		FROM packets ORDER BY epoch DESC LIMIT ?`, limit)
	if err != nil {
		return "Query failed: " + err.Error()
	}
	defer rows.Close()

	var b strings.Builder
	fmt.Fprintf(&b, "Last %d packets:\n", limit)
	n := 0
	for rows.Next() {
		var epoch sql.NullFloat64
		var src, dst, dns sql.NullString
		var port sql.NullInt64
		if err := rows.Scan(&epoch, &src, &dst, &port, &dns); err != nil {
			continue
		}
		ts := ""
		if epoch.Valid {
			ts = strconv.FormatFloat(epoch.Float64, 'f', 0, 64)
		}
		portStr := ""
		if port.Int64 > 0 {
			portStr = ":" + strconv.FormatInt(port.Int64, 10)
		}
		dnsStr := ""
		if dns.String != "" {
			dnsStr = " [" + dns.String + "]"
		}
		fmt.Fprintf(&b, "  %s %s → %s%s%s\n", ts, src.String, dst.String, portStr, dnsStr)
		n++
	}
	if n == 0 {
		b.WriteString("  (no packets)\n")
	}
	return b.String()
}

func connections(db *store.DB, arg string) string {
	if arg == "" {
		return "Usage: connections <ip>"
	}
	var b strings.Builder

	outRows, err := db.Query(`SELECT COALESCE(ip_dst,''), COUNT(*) AS cnt FROM packets
		WHERE ip_src LIKE ? ESCAPE '\' GROUP BY ip_dst ORDER BY cnt DESC LIMIT 20`, likePattern(arg))
	if err != nil {
		return "Query failed: " + err.Error()
	}
	fmt.Fprintf(&b, "%s connects to:\n", arg)
	n := 0
	for outRows.Next() {
		var ip sql.NullString
		var cnt int
		if err := outRows.Scan(&ip, &cnt); err != nil {
			continue
		}
		fmt.Fprintf(&b, "  → %s (×%d)\n", ip.String, cnt)
		n++
	}
	outRows.Close()
	if n == 0 {
		b.WriteString("  (none)\n")
	}

	inRows, err2 := db.Query(`SELECT COALESCE(ip_src,''), COUNT(*) AS cnt FROM packets
		WHERE ip_dst LIKE ? ESCAPE '\' GROUP BY ip_src ORDER BY cnt DESC LIMIT 20`, likePattern(arg))
	if err2 != nil {
		b.WriteString("\nQuery failed\n")
		return b.String()
	}
	defer inRows.Close()
	fmt.Fprintf(&b, "\n%s connects from:\n", arg)
	n = 0
	for inRows.Next() {
		var ip sql.NullString
		var cnt int
		if err := inRows.Scan(&ip, &cnt); err != nil {
			continue
		}
		fmt.Fprintf(&b, "  ← %s (×%d)\n", ip.String, cnt)
		n++
	}
	if n == 0 {
		b.WriteString("  (none)\n")
	}
	return b.String()
}

func services(db *store.DB, arg string) string {
	if arg == "" {
		return "Usage: services <ip>"
	}
	devices, err := db.Devices()
	if err != nil {
		return "Query failed: " + err.Error()
	}
	found := false
	var b strings.Builder
	for _, d := range devices {
		if !strings.Contains(d.IP, arg) {
			continue
		}
		found = true
		if d.Ports != "" {
			fmt.Fprintf(&b, "Services on %s:\n  %s\n", arg, d.Ports)
		} else {
			fmt.Fprintf(&b, "No port data for %s\n", arg)
		}
	}
	if !found {
		fmt.Fprintf(&b, "Unknown device: %s\n", arg)
	}
	return b.String()
}
