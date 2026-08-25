// Package tools implements the AI-callable tool surface: JSON schema
// definitions advertised to the model plus validated execution.
// Every tool validates its inputs before touching the system; SQL is limited
// to single read-only statements, nmap/tshark targets are strict IP literals,
// and web tools are only registered when the user opted in.
package tools

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hxmbl/hx_netkit/internal/belief"
	"github.com/hxmbl/hx_netkit/internal/config"
	netctx "github.com/hxmbl/hx_netkit/internal/context"
	"github.com/hxmbl/hx_netkit/internal/intel"
	"github.com/hxmbl/hx_netkit/internal/nlsearch"
	"github.com/hxmbl/hx_netkit/internal/nmap"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/textutil"
	"github.com/hxmbl/hx_netkit/internal/tshark"
	"github.com/hxmbl/hx_netkit/internal/websearch"
)

// Result is what a tool returns to the model.
type Result struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Output  string `json:"output"`
}

// Env carries everything tools need at runtime.
type Env struct {
	DB       *store.DB
	Cfg      config.Config
	Beliefs  *belief.System         // optional; nil disables get_beliefs/scan_ip belief updates
	Web      *websearch.Client      // nil unless user enabled web access
	Context  *netctx.NetworkContext // cached analysis of the current capture
	ExecNmap nmap.Runner            // injectable runner (defaults to exec)
}

func fn(name, desc string, props map[string]any, required ...string) map[string]any {
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        name,
			"description": desc,
			"parameters": map[string]any{
				"type":       "object",
				"properties": props,
				"required":   required,
			},
		},
	}
}

// Definitions builds the tool schema array advertised to Ollama.
// Web tools appear only when allowWeb is true.
func Definitions(allowWeb bool) []map[string]any {
	defs := []map[string]any{
		fn("sql",
			"Query the packet database directly. Read-only SELECT statements.",
			map[string]any{"query": map[string]any{"type": "string", "description": "SELECT query to run"}},
			"query"),
		fn("search",
			"Search the database for IPs, ports, DNS, connections. Query forms: 'ip <addr>', 'port <n>', 'dns <domain>', 'find <text>', 'devices', 'stats', 'talkers', 'recent', 'connections <ip>', 'services <ip>'.",
			map[string]any{"query": map[string]any{"type": "string", "description": "Search command string"}},
			"query"),
		fn("packets",
			"Pull raw packet evidence for an IP: timestamps, peers, ports, bytes, DNS. Filter by direction, peer, port, or time range.",
			map[string]any{
				"ip":        map[string]any{"type": "string", "description": "IP address to investigate"},
				"limit":     map[string]any{"type": "number", "description": "Max packets (default 20, max 200)"},
				"direction": map[string]any{"type": "string", "description": "'in', 'out', or 'both' (default)"},
				"peer":      map[string]any{"type": "string", "description": "Only packets to/from this peer IP"},
				"port":      map[string]any{"type": "number", "description": "Only packets on this port"},
				"after":     map[string]any{"type": "number", "description": "Only packets after this epoch time"},
				"before":    map[string]any{"type": "number", "description": "Only packets before this epoch time"},
			},
			"ip"),
		fn("network_context",
			"Get the full behavioral analysis summary for one IP: device classification, role, activity narrative, risk signals.",
			map[string]any{"ip": map[string]any{"type": "string", "description": "IP address to explain"}},
			"ip"),
		fn("devices",
			"List all discovered devices with OS guesses and open ports.",
			map[string]any{}),
		fn("anomalies",
			"List all behavioral anomaly findings sorted by confidence.",
			map[string]any{}),
		fn("threats",
			"Get the threat summary: high-confidence malicious indicators plus Bayesian belief state.",
			map[string]any{}),
		fn("nmap",
			"Ping-sweep a single IP to check if it is online.",
			map[string]any{"target": map[string]any{"type": "string", "description": "IP address to ping"}},
			"target"),
		fn("scan_ip",
			"Run nmap ping sweep + port/version scan on ONE IP (never CIDR). Updates the belief system.",
			map[string]any{"target": map[string]any{"type": "string", "description": "IP address to scan"}},
			"target"),
		fn("tshark",
			"Capture live traffic with an optional BPF filter (requires privileges). Default 10s, max 60s.",
			map[string]any{
				"filter":   map[string]any{"type": "string", "description": "BPF capture filter"},
				"duration": map[string]any{"type": "number", "description": "Seconds to capture (max 60)"},
			}),
	}
	defs = append(defs, fn("get_beliefs",
		"Get current belief distribution for all tracked or a specific IP: BOT/IOT/CAM/CLEAN/UNK probabilities + entropy.",
		map[string]any{"target": map[string]any{"type": "string", "description": "Optional IP to query (omit for all)"}}))
	if allowWeb {
		defs = append(defs,
			fn("websearch",
				"Search the public internet for information (user has allowed internet access).",
				map[string]any{"query": map[string]any{"type": "string", "description": "Search query"}}, "query"),
			fn("webfetch",
				"Fetch a public webpage as text (user has allowed internet access; local addresses are blocked).",
				map[string]any{"url": map[string]any{"type": "string", "description": "http(s) URL to fetch"}}, "url"),
		)
	}
	return defs
}

// ── validation ──────────────────────────────────────────────────────────────

// ValidTarget reports whether target is a bare IPv4 literal or comma/space/
// dash-separated list — never a hostname, CIDR, or injection vector.
func ValidTarget(target string) bool {
	if target == "" || len(target) > 64 {
		return false
	}
	if strings.Contains(target, "/") {
		return false
	}
	for _, c := range target {
		if !(c >= '0' && c <= '9' || c == '.' || c == ',' || c == '-' || c == ' ') {
			return false
		}
	}
	return true
}

var blockedSQLKeywords = []string{
	"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE",
	"EXEC", "EXECUTE", "ATTACH", "DETACH",
	"PRAGMA", "VACUUM", "REPLACE", "REINDEX",
}

// Keyword matchers use word boundaries so identifiers like created_at or
// printed don't trip the guard; quoted literals are stripped first so a
// string containing 'drop table' isn't mistaken for a statement.
var blockedSQLMatchers = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(blockedSQLKeywords))
	for i, kw := range blockedSQLKeywords {
		out[i] = regexp.MustCompile(`\b` + kw + `\b`)
	}
	return out
}()

func stripSQLLiterals(q string) string {
	var b strings.Builder
	inSingle, inDouble := false, false
	inLineComment, inBlockComment := false, false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case inLineComment:
			if c == '\n' {
				inLineComment = false
				b.WriteByte(c)
			}
		case inBlockComment:
			if c == '*' && i+1 < len(q) && q[i+1] == '/' {
				inBlockComment = false
				i++
				b.WriteByte(' ')
			}
		case inSingle:
			if c == '\'' {
				if i+1 < len(q) && q[i+1] == '\'' {
					i++ // escaped ''
					continue
				}
				inSingle = false
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			}
		case c == '\'' && !inBlockComment:
			inSingle = true
		case c == '"' && !inBlockComment:
			inDouble = true
		case c == '-' && i+1 < len(q) && q[i+1] == '-':
			inLineComment = true
			i++
		case c == '/' && i+1 < len(q) && q[i+1] == '*':
			inBlockComment = true
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// SafeSQL enforces read-only, single-statement queries.
func SafeSQL(query string) error {
	q := strings.TrimSpace(query)
	if q == "" {
		return fmt.Errorf("empty query")
	}
	if strings.Count(q, ";") > 1 || (strings.Count(q, ";") == 1 && !strings.HasSuffix(q, ";")) {
		return fmt.Errorf("only single statements are allowed")
	}
	stripped := strings.ToUpper(stripSQLLiterals(q))
	for i, re := range blockedSQLMatchers {
		if re.MatchString(stripped) {
			return fmt.Errorf("keyword '%s' is not allowed", blockedSQLKeywords[i])
		}
	}
	for _, prefix := range []string{"SELECT", "WITH", "EXPLAIN"} {
		if strings.HasPrefix(stripped, prefix) {
			return nil
		}
	}
	return fmt.Errorf("only SELECT/WITH/EXPLAIN queries are allowed")
}

// SafeSearchText rejects control characters and shell metacharacters.
func SafeSearchText(q string) bool {
	if q == "" || len(q) > 128 {
		return false
	}
	for _, c := range q {
		switch c {
		case ';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r':
			return false
		}
	}
	return true
}

// SafeBPF rejects filters containing characters that could break out of argv
// quoting when re-parsed downstream.
func SafeBPF(f string) bool {
	if f == "" {
		return true
	}
	if len(f) > 256 {
		return false
	}
	for _, c := range f {
		switch c {
		case ';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '"', '\'':
			return false
		}
	}
	return true
}

// ── arg helpers ─────────────────────────────────────────────────────────────

func strArg(args map[string]any, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

func intArg(args map[string]any, key string, def int64) int64 {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case string:
			if i, err := strconv.ParseInt(n, 10, 64); err == nil {
				return i
			}
		case int64:
			return n
		}
	}
	return def
}

func floatArg(args map[string]any, key string, def float64) float64 {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case string:
			if f, err := strconv.ParseFloat(n, 64); err == nil {
				return f
			}
		}
	}
	return def
}

func clamp(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// resolveCount resolves an integer argument where an explicit zero or
// negative value means "use the default", not the minimum. (The model
// routinely sends duration:0 expecting defaults.)
func resolveCount(args map[string]any, key string, def, lo, hi int64) int64 {
	if _, present := args[key]; !present {
		return def
	}
	v := intArg(args, key, def)
	if v <= 0 {
		return def
	}
	return clamp(v, lo, hi)
}

// Execute dispatches one validated tool call.
func (e *Env) Execute(ctx context.Context, name string, args map[string]any) Result {
	switch name {
	case "sql":
		return e.toolSQL(strArg(args, "query"))
	case "search":
		return e.toolSearch(strArg(args, "query"))
	case "packets":
		return e.toolPackets(args)
	case "network_context":
		return e.toolNetworkContext(strArg(args, "ip"))
	case "devices":
		return e.toolDevices()
	case "anomalies":
		return e.toolAnomalies()
	case "threats":
		return e.toolThreats()
	case "nmap":
		return e.toolNmapPing(strArg(args, "target"))
	case "scan_ip":
		return e.toolScanIP(ctx, strArg(args, "target"))
	case "tshark":
		return e.toolTShark(strArg(args, "filter"), resolveCount(args, "duration", 10, 1, 60))
	case "get_beliefs":
		target := strArg(args, "target")
		if target == "" {
			if e.Beliefs == nil {
				return Result{name, "Belief system not initialized", "No belief data available."}
			}
			out := e.Beliefs.FormatAll()
			return Result{name, fmt.Sprintf("Beliefs for %d IPs", e.Beliefs.Len()), out}
		}
		if e.Beliefs == nil {
			return Result{name, "Belief system not initialized", "No belief data available."}
		}
		if line, ok := e.Beliefs.FormatIP(target); ok {
			return Result{name, "Beliefs for " + target, line}
		}
		return Result{name, "IP not tracked", fmt.Sprintf("IP %s has no belief data. Use scan_ip to start tracking.", target)}
	case "websearch":
		return e.toolWebSearch(ctx, strArg(args, "query"))
	case "webfetch":
		return e.toolWebFetch(ctx, strArg(args, "url"))
	default:
		return Result{name, "Unknown tool", fmt.Sprintf("Tool '%s' does not exist.", name)}
	}
}

// ── implementations ─────────────────────────────────────────────────────────

func (e *Env) toolSQL(query string) Result {
	if err := SafeSQL(query); err != nil {
		return Result{"sql", "Rejected unsafe SQL", err.Error()}
	}
	cols, rows, err := e.DB.QueryRows(strings.TrimSuffix(query, ";"), 20)
	if err != nil {
		return Result{"sql", "Query failed", "Error: " + err.Error()}
	}
	var b strings.Builder
	b.WriteString(strings.Join(cols, " | ") + "\n")
	for _, row := range rows {
		b.WriteString(strings.Join(row, " | ") + "\n")
	}
	return Result{"sql", fmt.Sprintf("%d rows returned", len(rows)), strings.TrimRight(b.String(), "\n")}
}

func (e *Env) toolSearch(query string) Result {
	if !SafeSearchText(query) {
		return Result{"search", "Invalid search", "Search contains invalid characters."}
	}
	out := nlsearch.Execute(e.DB, query)
	lines := strings.Count(out, "\n")
	return Result{"search", fmt.Sprintf("Search returned ~%d lines", lines), out}
}

func (e *Env) toolPackets(args map[string]any) Result {
	ip := strArg(args, "ip")
	limit := resolveCount(args, "limit", 20, 1, 200)
	direction := strArg(args, "direction")
	if direction == "" {
		direction = "both"
	}
	peer := strArg(args, "peer")
	port := intArg(args, "port", 0)
	after := floatArg(args, "after", 0)
	before := floatArg(args, "before", 0)

	if !ValidTarget(ip) {
		return Result{"packets", "Invalid IP", fmt.Sprintf("Rejected: '%s' is not a valid IP address", ip)}
	}
	if peer != "" && !ValidTarget(peer) {
		return Result{"packets", "Invalid peer", fmt.Sprintf("Rejected: '%s' is not a valid IP address", peer)}
	}

	var conds []string
	switch direction {
	case "out":
		conds = append(conds, "ip_src = ?")
	case "in":
		conds = append(conds, "ip_dst = ?")
	default:
		conds = append(conds, "(ip_src = ? OR ip_dst = ?)")
	}
	var params []any
	addParam := func(v any) {
		params = append(params, v)
		switch direction {
		case "out", "in":
		default:
			params = append(params, v)
		}
	}
	addParam(ip)
	if peer != "" {
		conds = append(conds, "(ip_src = ? OR ip_dst = ?)")
		params = append(params, peer, peer)
	}
	if port > 0 {
		conds = append(conds, "(tcp_src_port = ? OR tcp_dst_port = ? OR udp_src_port = ? OR udp_dst_port = ?)")
		for i := 0; i < 4; i++ {
			params = append(params, port)
		}
	}
	if after > 0 {
		conds = append(conds, "epoch > ?")
		params = append(params, after)
	}
	if before > 0 {
		conds = append(conds, "epoch < ?")
		params = append(params, before)
	}

	query := fmt.Sprintf(`SELECT epoch, COALESCE(ip_src,''), COALESCE(ip_dst,''),
		COALESCE(tcp_src_port,0), COALESCE(tcp_dst_port,0),
		COALESCE(udp_src_port,0), COALESCE(udp_dst_port,0),
		COALESCE(dns_query,''), COALESCE(frame_len,0)
		FROM packets WHERE %s ORDER BY epoch DESC LIMIT %d`,
		strings.Join(conds, " AND "), limit)

	rows, err := e.DB.Query(query, params...)
	if err != nil {
		return Result{"packets", "Query failed", "SQL error: " + err.Error()}
	}
	defer rows.Close()

	peerCounts := map[string]int{}
	portCounts := map[uint32]int{}
	dnsSeen := map[string]bool{}
	var dnsQueries []string
	totalBytes := uint64(0)
	count := 0
	var samples []string

	for rows.Next() {
		var epoch sql.NullFloat64
		var src, dst, dns sql.NullString
		var tsp, tdp, usp, udp_, fl sql.NullInt64
		if err := rows.Scan(&epoch, &src, &dst, &tsp, &tdp, &usp, &udp_, &dns, &fl); err != nil || !epoch.Valid {
			continue // legacy rows with NULL epochs carry no evidence
		}
		count++
		epochVal := epoch.Float64
		srcPort := maxI64(tsp.Int64, usp.Int64)
		dstPort := maxI64(tdp.Int64, udp_.Int64)
		bytes := uint64(fl.Int64)
		totalBytes += bytes

		isOut := src.String == ip
		peerStr := dst.String
		displayPort := dstPort
		arrow := "↑"
		if !isOut {
			peerStr = src.String
			displayPort = srcPort
			arrow = "↓"
		}
		peerCounts[peerStr]++
		if displayPort > 0 {
			portCounts[uint32(displayPort)]++
		}
		if dns.String != "" && !dnsSeen[dns.String] {
			dnsSeen[dns.String] = true
			dnsQueries = append(dnsQueries, dns.String)
		}
		if len(samples) < 20 {
			dnsStr := ""
			if dns.String != "" {
				dnsStr = " [" + dns.String + "]"
			}
			samples = append(samples, fmt.Sprintf("%s %s %s:%d → %s:%d  %dB%s",
				formatDT(epochVal), arrow, src.String, srcPort, peerStr, dstPort, bytes, dnsStr))
		}
	}

	label := "to/from " + ip
	switch direction {
	case "out":
		label = "outbound from " + ip
	case "in":
		label = "inbound to " + ip
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d packets %s (%d bytes)\n", count, label, totalBytes)

	if len(peerCounts) > 0 {
		b.WriteString("\nTop peers:\n")
		for _, p := range topStrings(peerCounts, 10) {
			fmt.Fprintf(&b, "  %5dx  %s\n", p.count, p.key)
		}
	}
	if len(portCounts) > 0 {
		b.WriteString("\nTop ports:\n")
		type pc struct {
			port  uint32
			count int
		}
		list := make([]pc, 0, len(portCounts))
		for pt, c := range portCounts {
			list = append(list, pc{pt, c})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].count > list[j].count })
		for i, x := range list {
			if i == 10 {
				break
			}
			fmt.Fprintf(&b, "  %5dx  port %d\n", x.count, x.port)
		}
	}
	if len(dnsQueries) > 0 {
		fmt.Fprintf(&b, "\nDNS (%d unique):\n", len(dnsQueries))
		for i, q := range dnsQueries {
			if i == 10 {
				break
			}
			b.WriteString("  " + q + "\n")
		}
	}
	if len(samples) > 0 {
		b.WriteString("\nSample:\n")
		for _, s := range samples {
			b.WriteString("  " + s + "\n")
		}
	}

	return Result{"packets", fmt.Sprintf("%d packets %s — %d peers, %d ports, %d DNS",
		count, label, len(peerCounts), len(portCounts), len(dnsQueries)), strings.TrimRight(b.String(), "\n")}
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func formatDT(epoch float64) string {
	secs := int64(epoch) % 86400
	h := secs / 3600
	m := (secs / 60) % 60
	s := secs % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

type kv struct {
	key   string
	count int
}

func topStrings(m map[string]int, n int) []kv {
	list := make([]kv, 0, len(m))
	for k, c := range m {
		list = append(list, kv{k, c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].key < list[j].key
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func (e *Env) deviceInfos() []intel.DeviceInfo {
	if e.Context == nil {
		return nil
	}
	return e.Context.Devices
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (e *Env) toolNetworkContext(ip string) Result {
	if !ValidTarget(ip) {
		return Result{"network_context", "Invalid IP", fmt.Sprintf("Rejected: '%s' is not a valid IP", ip)}
	}
	if e.Context == nil {
		return Result{"network_context", "No analysis loaded", "Network context is unavailable."}
	}
	p, ok := e.Context.Profiles[ip]
	if !ok {
		return Result{"network_context", "IP unknown", fmt.Sprintf("No traffic profile for %s in this capture.", ip)}
	}
	var ipFindings []intel.Finding
	for i := range e.Context.Findings {
		if e.Context.Findings[i].IP == ip {
			ipFindings = append(ipFindings, e.Context.Findings[i])
		}
	}
	summaries := intel.GenerateNarratives(map[string]*intel.Profile{ip: p}, e.deviceInfos(), ipFindings)
	var parts []string
	for _, s := range summaries {
		parts = append(parts, s.String())
	}
	for i := range ipFindings {
		parts = append(parts, "Finding: "+ipFindings[i].String())
	}
	return Result{"network_context", fmt.Sprintf("Behavioral profile for %s", ip), strings.Join(parts, "\n")}
}

func (e *Env) toolDevices() Result {
	rows, err := e.DB.Devices()
	if err != nil {
		return Result{"devices", "Query failed", err.Error()}
	}
	if len(rows) == 0 {
		return Result{"devices", "No devices known", "No devices discovered yet. Run capture first."}
	}
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		osG := derefStr(r.OSGuess)
		if osG == "" {
			osG = "?"
		}
		host := derefStr(r.Hostname)
		if host == "" {
			host = "?"
		}
		ports := r.Ports
		if ports == "" {
			ports = "no open ports"
		}
		lines = append(lines, fmt.Sprintf("%s (%s) [%s] — %s", r.IP, host, osG, ports))
	}
	return Result{"devices", fmt.Sprintf("%d known devices", len(rows)), strings.Join(lines, "\n")}
}

func (e *Env) toolAnomalies() Result {
	if e.Context == nil {
		return Result{"anomalies", "No analysis loaded", "Network context is unavailable."}
	}
	var lines []string
	for i := range e.Context.Findings {
		f := &e.Context.Findings[i]
		if f.Kind == intel.KUnknown {
			continue
		}
		detail := textutil.Truncate(f.Detail, 150)
		lines = append(lines, fmt.Sprintf("%s [%s] %d%%: %s", f.IP, f.Kind, f.ConfidencePct(), detail))
	}
	if len(lines) == 0 {
		return Result{"anomalies", "No anomalies", "No behavioral anomalies detected."}
	}
	return Result{"anomalies", fmt.Sprintf("%d findings", len(lines)), strings.Join(lines, "\n")}
}

func (e *Env) toolThreats() Result {
	if e.Context == nil {
		return Result{"threats", "No analysis loaded", "Network context is unavailable."}
	}
	threatKinds := map[intel.Kind]bool{
		intel.KBot: true, intel.KScanner: true, intel.KBeacon: true, intel.KTor: true,
		intel.KC2Beacon: true, intel.KDataExfil: true, intel.KLateralMovement: true,
		intel.KNetworkRecon: true, intel.KDNSProfiler: true,
	}
	var lines []string
	for i := range e.Context.Findings {
		f := &e.Context.Findings[i]
		if threatKinds[f.Kind] {
			lines = append(lines, fmt.Sprintf("- %s [%s] (%d%%): %s", f.IP, f.Kind, f.ConfidencePct(), f.Detail))
		}
	}
	if len(lines) == 0 {
		return Result{"threats", "Clean", "No significant threats detected."}
	}
	out := strings.Join(lines, "\n")
	if e.Beliefs != nil {
		out += "\n\nBelief state:\n" + e.Beliefs.FormatAll()
	}
	return Result{"threats", fmt.Sprintf("%d threat signals", len(lines)), out}
}

func (e *Env) runner() nmap.Runner {
	if e.ExecNmap != nil {
		return e.ExecNmap
	}
	return nmap.ExecRunner{}
}

func (e *Env) toolNmapPing(target string) Result {
	if !ValidTarget(target) {
		return Result{"nmap", "Invalid target", fmt.Sprintf("Rejected: '%s' is not a valid IP/CIDR-free target", target)}
	}
	out, err := e.runner().Run("-sn", "-T5", "--max-retries", "1", "--host-timeout", "5s", target)
	if err != nil {
		return Result{"nmap", "nmap failed", "Error: " + err.Error()}
	}
	alive := strings.Contains(string(out), "Host is up")
	status := "down"
	if alive {
		status = "up"
	}
	return Result{"nmap", fmt.Sprintf("%s → %s", target, status), fmt.Sprintf("IP: %s\nStatus: %s", target, status)}
}

func (e *Env) toolScanIP(ctx context.Context, target string) Result {
	if !ValidTarget(target) {
		return Result{"scan_ip", "Invalid target", fmt.Sprintf("Rejected: '%s' is not a valid IP address", target)}
	}
	r := e.runner()
	pingOut, err := r.Run("-sn", "-T5", "--max-retries", "1", "--host-timeout", "5s", target)
	if err != nil {
		return Result{"scan_ip", "nmap failed", "Error: " + err.Error()}
	}
	alive := strings.Contains(string(pingOut), "Host is up")

	var ports []uint32
	var osReal string
	if alive {
		xmlOut, err := r.Run("-sV", "--top-ports", "100", "--open", "-oX", "-", "-T4", "--min-rate", "1000", target)
		if err == nil {
			ports = nmap.ExtractOpenPorts(xmlOut)
		}
		osOut, err := r.Run("-O", "--open", "-oX", "-", "-T4", "--min-rate", "1000", target)
		if err == nil {
			if devs := nmap.ParseXML(osOut); len(devs) > 0 {
				osReal = devs[0].OSGuess
			}
		}
	}
	osHint := osReal
	if osHint == "" && alive && len(ports) > 0 {
		osHint = nmap.GuessOSFromPorts(ports)
	}
	if osHint == "" {
		osHint = "unknown"
	}
	if e.Beliefs != nil {
		e.Beliefs.Ensure(target)
		e.Beliefs.UpdateFromNmap(target, alive, ports)
	}
	status := "down"
	if alive {
		status = "up"
	}
	portsStr := "no open ports"
	if len(ports) > 0 {
		strs := make([]string, len(ports))
		for i, p := range ports {
			strs[i] = strconv.FormatUint(uint64(p), 10)
		}
		portsStr = fmt.Sprintf("%d open ports: %s", len(ports), strings.Join(strs, ", "))
	}
	return Result{"scan_ip", fmt.Sprintf("%s → %s (%s)", target, status, osHint),
		fmt.Sprintf("IP: %s\nStatus: %s\nOS: %s\n%s", target, status, osHint, portsStr)}
}

func (e *Env) toolTShark(filter string, duration int64) Result {
	duration = clamp(duration, 1, 60)
	if !SafeBPF(filter) {
		return Result{"tshark", "Invalid filter", "Rejected: filter contains invalid characters"}
	}
	iface := e.Cfg.Interface
	captureCtx, cancel := context.WithTimeout(context.Background(), timeDuration(duration)*2)
	defer cancel()

	cmd := sudoCommand("tshark", tshark.Args(iface, filter)...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{"tshark", "tshark failed", "Error: " + err.Error()}
	}
	if err := cmd.Start(); err != nil {
		msg := err.Error()
		if tail := strings.TrimSpace(stderrBuf.String()); tail != "" {
			msg += ": " + textutil.Truncate(tail, 200)
		}
		return Result{"tshark", "tshark failed", "Error: " + msg}
	}
	go func() {
		timeSleep(timeDuration(duration))
		stopProcess(cmd)
	}()

	var lines []string
	tmp := make([]byte, 4096)
	var carry string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			n, err := stdout.Read(tmp)
			if n > 0 {
				carry += string(tmp[:n])
				for {
					idx := indexByte(carry, '\n')
					if idx < 0 {
						break
					}
					line := carry[:idx]
					carry = carry[idx+1:]
					if tshark.Skippable(line) {
						continue
					}
					if pkt, ok := tshark.ParseLine(line); ok {
						dns := ""
						if pkt.DNSQuery != "" {
							dns = " [" + pkt.DNSQuery + "]"
						}
						lines = append(lines, "→ "+pkt.IPDst+dns)
						if len(lines) >= 50 {
							stopProcess(cmd)
							return
						}
					}
				}
			}
			if err != nil {
				return
			}
			select {
			case <-captureCtx.Done():
				return
			default:
			}
		}
	}()
	select {
	case <-done:
	case <-captureCtx.Done():
	}
	waitProcess(cmd)

	output := strings.Join(lines, "\n")
	if len(lines) == 0 {
		if tail := strings.TrimSpace(stderrBuf.String()); tail != "" {
			output += "\n\ntshark stderr: " + textutil.Truncate(tail, 300)
		}
	}
	return Result{"tshark", fmt.Sprintf("Captured %d packets (%ds)", len(lines), duration), output}
}

func (e *Env) toolWebSearch(ctx context.Context, query string) Result {
	if e.Web == nil {
		return Result{"websearch", "Disabled", "Internet access is disabled. Enable [web] in config or pass --allow-web."}
	}
	if query == "" || len(query) > 200 {
		return Result{"websearch", "Invalid query", "Query must be 1-200 characters."}
	}
	results, err := e.Web.Search.Search(ctx, query)
	if err != nil {
		return Result{"websearch", "Search failed", "Error: " + err.Error()}
	}
	if len(results) == 0 {
		return Result{"websearch", fmt.Sprintf("No results for '%s'", query), "No search results found. Try different keywords."}
	}
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = fmt.Sprintf("%s %s\n%s", r.Title, r.URL, r.Snippet)
	}
	return Result{"websearch", fmt.Sprintf("Found %d results for '%s'", len(results), query), strings.Join(out, "\n\n")}
}

func (e *Env) toolWebFetch(ctx context.Context, url string) Result {
	if e.Web == nil {
		return Result{"webfetch", "Disabled", "Internet access is disabled. Enable [web] in config or pass --allow-web."}
	}
	text, status, err := e.Web.FetchPage(ctx, url, 4000)
	if err != nil {
		return Result{"webfetch", "Fetch failed", "Error: " + err.Error()}
	}
	return Result{"webfetch", fmt.Sprintf("Fetched %s (status %d)", url, status), text}
}
