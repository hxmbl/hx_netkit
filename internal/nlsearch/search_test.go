package nlsearch

import (
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/store"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	_ = db.InsertPacket(1000, "192.168.1.10", "93.184.216.34", 49200, 443, 0, 0, "", "{}", 1400)
	_ = db.InsertPacket(1001, "192.168.1.10", "93.184.216.35", 49201, 53, 0, 0, "example.com", "{}", 90)
	_ = db.InsertPacket(1002, "192.168.1.11", "192.168.1.10", 51000, 8080, 0, 0, "", "{}", 200)
	_ = db.UpsertDevice("192.168.1.10", "AA:BB", "nas.local", "Synology", "Linux", "443/open/https", 900)
	return db
}

func TestIPSearch(t *testing.T) {
	out := Execute(testDB(t), "ip 192.168.1.10")
	if !strings.Contains(out, "Traffic for 192.168.1.10") || !strings.Contains(out, "93.184.216.34") {
		t.Errorf("ip search broken:\n%s", out)
	}
	if out := Execute(testDB(t), "ip"); !strings.Contains(out, "Usage") {
		t.Error("missing usage hint")
	}
}

func TestPortSearchValidation(t *testing.T) {
	db := testDB(t)
	if out := Execute(db, "port 70000"); !strings.Contains(out, "Invalid port") {
		t.Errorf("port validation missing:\n%s", out)
	}
	if out := Execute(db, "port 443"); strings.Contains(out, "Invalid") {
		t.Errorf("valid port rejected:\n%s", out)
	}
	if out := Execute(db, "port"); !strings.Contains(out, "Usage") {
		t.Error("missing usage hint")
	}
}

func TestDNSSearch(t *testing.T) {
	out := Execute(testDB(t), "dns example")
	if !strings.Contains(out, "example.com") {
		t.Errorf("dns search failed:\n%s", out)
	}
}

func TestFindText(t *testing.T) {
	out := Execute(testDB(t), "find example.com")
	if !strings.Contains(out, "Results for 'example.com'") {
		t.Errorf("find failed:\n%s", out)
	}
}

func TestDevicesStatsTalkersRecentConnectionsServices(t *testing.T) {
	db := testDB(t)

	if out := Execute(db, "devices"); !strings.Contains(out, "nas.local") {
		t.Errorf("devices failed:\n%s", out)
	}
	if out := Execute(db, "stats"); !strings.Contains(out, "3 packets") {
		t.Errorf("stats failed:\n%s", out)
	}
	if out := Execute(db, "talkers 2"); !strings.Contains(out, "Top 2 talkers") {
		t.Errorf("talkers failed:\n%s", out)
	}
	if out := Execute(db, "recent 2"); !strings.Contains(out, "Last 2 packets") {
		t.Errorf("recent failed:\n%s", out)
	}
	if out := Execute(db, "connections 192.168.1.10"); !strings.Contains(out, "connects to") || !strings.Contains(out, "connects from") {
		t.Errorf("connections failed:\n%s", out)
	}
	if out := Execute(db, "services 192.168.1.10"); !strings.Contains(out, "443/open/https") {
		t.Errorf("services failed:\n%s", out)
	}
}

func TestAliasesAndHelpAndUnknown(t *testing.T) {
	db := testDB(t)
	if out := Execute(db, "?"); !strings.Contains(out, "Commands:") {
		t.Error("help alias failed")
	}
	if out := Execute(db, "host 192.168.1.11"); !strings.Contains(out, "Traffic for") {
		t.Error("host alias failed")
	}
	if out := Execute(db, "bogus stuff"); !strings.Contains(out, "Unknown command: 'bogus'") {
		t.Errorf("unknown command handling failed:\n%s", out)
	}
	if out := Execute(db, ""); out != "" {
		t.Errorf("empty input should return empty string, got %q", out)
	}
	if out := Execute(db, "quit"); out != "" {
		t.Errorf("quit should return empty string, got %q", out)
	}
}

func TestEmptyResultsAreExplicit(t *testing.T) {
	db := testDB(t)
	if out := Execute(db, "port 9999"); !strings.Contains(out, "(no traffic on this port)") {
		t.Errorf("empty port results not explicit:\n%s", out)
	}
	if out := Execute(db, "dns zzzznothing"); !strings.Contains(out, "(no DNS matches)") {
		t.Errorf("empty dns results not explicit:\n%s", out)
	}
}
