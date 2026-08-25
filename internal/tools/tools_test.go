package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/belief"
	"github.com/hxmbl/hx_netkit/internal/store"
)

func testEnv(t *testing.T) *Env {
	t.Helper()
	db, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	for i := 0; i < 5; i++ {
		_ = db.InsertPacket(1000+float64(i), "192.168.1.10", "93.184.216.34", 49200, 443, 0, 0, "", "{}", 1400)
	}
	_ = db.InsertPacket(1005, "192.168.1.10", "93.184.216.34", 0, 0, 5353, 53, "example.com", "{}", 90)
	_ = db.UpsertDevice("192.168.1.10", "AA:BB", "nas.local", "Synology", "Linux", "443/open/https", 900)
	return &Env{DB: db}
}

func TestValidTarget(t *testing.T) {
	valid := []string{"192.168.1.1", "8.8.8.8,8.8.4.4", "10.0.0.1-10.0.0.9"}
	invalid := []string{"", "example.com", "192.168.1.0/24", "1;rm -rf /", "$(id)", strings.Repeat("a", 65), "1.2.3.4&&whoami"}
	for _, v := range valid {
		if !ValidTarget(v) {
			t.Errorf("ValidTarget(%q) = false, want true", v)
		}
	}
	for _, iv := range invalid {
		if ValidTarget(iv) {
			t.Errorf("ValidTarget(%q) = true, want false", iv)
		}
	}
}

func TestSafeSQL(t *testing.T) {
	good := []string{
		"SELECT * FROM packets",
		"select count(*) from packets",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"SELECT * FROM packets;",
		"EXPLAIN QUERY PLAN SELECT 1",
	}
	bad := []string{
		"", "DROP TABLE packets", "DELETE FROM packets",
		"SELECT 1; DROP TABLE packets", "UPDATE packets SET epoch=1",
		"INSERT INTO packets VALUES (1)", "ATTACH DATABASE 'x' AS y",
		"PRAGMA journal_mode", "VACUUM",
	}
	for _, q := range good {
		if err := SafeSQL(q); err != nil {
			t.Errorf("SafeSQL(%q) = %v, want ok", q, err)
		}
	}
	for _, q := range bad {
		if err := SafeSQL(q); err == nil {
			t.Errorf("SafeSQL(%q) = nil error, want rejection", q)
		}
	}
}

func TestSafeSearchTextAndBPF(t *testing.T) {
	if SafeSearchText("ip 1.2.3") != true {
		t.Error("benign search rejected")
	}
	for _, bad := range []string{"", "; drop", "a|b", "$(x)", strings.Repeat("x", 129)} {
		if SafeSearchText(bad) {
			t.Errorf("SafeSearchText(%q) should be false", bad)
		}
	}
	if !SafeBPF("") || !SafeBPF("tcp port 443") {
		t.Error("benign BPF rejected")
	}
	for _, bad := range []string{"tcp;id", "a&b", "`cmd`", strings.Repeat("x", 257)} {
		if SafeBPF(bad) {
			t.Errorf("SafeBPF(%q) should be false", bad)
		}
	}
}

func TestDefinitionsIncludeCoreAndGateWeb(t *testing.T) {
	names := func(web bool) map[string]bool {
		out := map[string]bool{}
		for _, d := range Definitions(web) {
			fnMap := d["function"].(map[string]any)
			out[fnMap["name"].(string)] = true
		}
		return out
	}

	core := names(false)
	for _, want := range []string{"sql", "search", "packets", "nmap", "scan_ip", "tshark", "get_beliefs", "network_context", "devices", "anomalies", "threats"} {
		if !core[want] {
			t.Errorf("missing core tool %s", want)
		}
	}
	if core["websearch"] || core["webfetch"] {
		t.Error("web tools must be absent when web disabled")
	}
	withWeb := names(true)
	if !withWeb["websearch"] || !withWeb["webfetch"] {
		t.Error("web tools missing when enabled")
	}
}

func TestSQLToolRejectsAndExecutes(t *testing.T) {
	env := testEnv(t)

	res := env.Execute(context.Background(), "sql", map[string]any{"query": "DROP TABLE packets"})
	if res.Summary != "Rejected unsafe SQL" {
		t.Errorf("dangerous SQL executed!: %+v", res)
	}

	res = env.Execute(context.Background(), "sql", map[string]any{"query": "SELECT COUNT(*) AS n FROM packets"})
	if !strings.Contains(res.Output, "6") {
		t.Errorf("count query output = %q", res.Output)
	}
}

func TestPacketsToolFilters(t *testing.T) {
	env := testEnv(t)

	res := env.Execute(context.Background(), "packets", map[string]any{"ip": "not an ip"})
	if res.Summary != "Invalid IP" {
		t.Errorf("invalid ip accepted: %+v", res)
	}

	res = env.Execute(context.Background(), "packets", map[string]any{"ip": "192.168.1.10", "direction": "out"})
	if !strings.Contains(res.Output, "6 packets outbound from 192.168.1.10") {
		t.Errorf("outbound count wrong:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "93.184.216.34") || !strings.Contains(res.Output, "example.com") {
		t.Errorf("peer/dns evidence missing:\n%s", res.Output)
	}

	res = env.Execute(context.Background(), "packets", map[string]any{"ip": "192.168.1.10", "port": float64(443)})
	if !strings.Contains(res.Output, "port 443") && !strings.Contains(res.Output, ":443") {
		t.Errorf("port filter failed:\n%s", res.Output)
	}

	res = env.Execute(context.Background(), "packets", map[string]any{"ip": "192.168.1.10", "after": float64(1003)})
	if !strings.Contains(res.Output, "2 packets to/from") {
		t.Errorf("time filter failed:\n%s", res.Output)
	}
}

func TestSearchTool(t *testing.T) {
	env := testEnv(t)
	res := env.Execute(context.Background(), "search", map[string]any{"query": "devices"})
	if !strings.Contains(res.Output, "nas.local") {
		t.Errorf("search tool failed:\n%s", res.Output)
	}
	res = env.Execute(context.Background(), "search", map[string]any{"query": "; bad"})
	if res.Summary != "Invalid search" {
		t.Errorf("malicious search accepted: %+v", res)
	}
}

func TestDevicesAnomaliesThreats(t *testing.T) {
	env := testEnv(t)

	res := env.Execute(context.Background(), "devices", nil)
	if !strings.Contains(res.Output, "192.168.1.10") {
		t.Errorf("devices tool failed: %s", res.Output)
	}
	// No analysis context → graceful degradation.
	for _, name := range []string{"anomalies", "threats"} {
		res = env.Execute(context.Background(), name, nil)
		if res.Summary != "No analysis loaded" {
			t.Errorf("%s without context should degrade gracefully: %+v", name, res)
		}
	}
}

func TestGetBeliefsWithoutSystem(t *testing.T) {
	env := testEnv(t)
	res := env.Execute(context.Background(), "get_beliefs", nil)
	if res.Summary != "Belief system not initialized" {
		t.Errorf("unexpected: %+v", res)
	}
	env.Beliefs = belief.New()
	env.Beliefs.Ensure("10.0.0.1")
	res = env.Execute(context.Background(), "get_beliefs", nil)
	if !strings.Contains(res.Output, "10.0.0.1") {
		t.Errorf("belief listing broken: %s", res.Output)
	}
	res = env.Execute(context.Background(), "get_beliefs", map[string]any{"target": "10.9.9.9"})
	if !strings.Contains(res.Output, "no belief data") {
		t.Errorf("unknown IP belief handling wrong: %s", res.Output)
	}
}

func TestNmapToolValidatesTargetBeforeExecution(t *testing.T) {
	env := testEnv(t)
	env.ExecNmap = fakeRunner{output: ""}
	res := env.Execute(context.Background(), "nmap", map[string]any{"target": "bad/target"})
	if res.Summary != "Invalid target" {
		t.Errorf("target validation bypassed runner: %+v", res)
	}
	res = env.Execute(context.Background(), "nmap", map[string]any{"target": "127.0.0.1"})
	if res.Output != "IP: 127.0.0.1\nStatus: down" {
		t.Errorf("fake runner not used or parsing wrong: %+v", res)
	}
}

type fakeRunner struct{ output string }

func (f fakeRunner) Run(args ...string) ([]byte, error) { return []byte(f.output), nil }

func TestWebToolsDisabledWithoutClient(t *testing.T) {
	env := testEnv(t)
	res := env.Execute(context.Background(), "websearch", map[string]any{"query": "test"})
	if res.Summary != "Disabled" {
		t.Errorf("websearch should be disabled: %+v", res)
	}
	res = env.Execute(context.Background(), "webfetch", map[string]any{"url": "https://example.com"})
	if res.Summary != "Disabled" {
		t.Errorf("webfetch should be disabled: %+v", res)
	}
}

func TestUnknownTool(t *testing.T) {
	env := testEnv(t)
	res := env.Execute(context.Background(), "self_destruct", nil)
	if !strings.Contains(res.Output, "does not exist") {
		t.Errorf("unknown tool handling wrong: %+v", res)
	}
}
