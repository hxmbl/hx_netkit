package context

import (
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/intel"
	"github.com/hxmbl/hx_netkit/internal/store"
)

func buildTestContext(t *testing.T, corporate bool) (*store.DB, *NetworkContext) {
	t.Helper()
	db, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Scanner-like traffic from .200 → many ports on gateway.
	for i := 0; i < 25; i++ {
		_ = db.InsertPacket(1000+float64(i), "192.168.1.200", "192.168.1.1", 40000, int64(1000+i), 0, 0, "", "", 60)
	}
	// Browser-ish traffic from .50.
	for i := 0; i < 12; i++ {
		_ = db.InsertPacket(1000+float64(i)*2, "192.168.1.50", "198.51.100.9", int64(49300+i), 443, 0, 0, "site.example.com", "", 1400)
	}
	_ = db.UpsertDevice("192.168.1.1", "AA:BB:CC", "gateway.local", "Ubiquiti", "Linux", "22/open/ssh", 900)
	_ = db.RecordScan("192.168.1.0/24", "<xml/>", "192.168.1.1 (gateway.local) — Linux [22/open/ssh]", 900)

	c, err := Build(db, corporate)
	if err != nil {
		t.Fatal(err)
	}
	return db, c
}

func TestBuildProducesAnalysis(t *testing.T) {
	_, c := buildTestContext(t, false)

	if c.PacketCount != 37 {
		t.Errorf("packet count = %d, want 37", c.PacketCount)
	}
	if len(c.Profiles) == 0 {
		t.Fatal("no profiles built")
	}
	if len(c.Findings) == 0 {
		t.Error("no findings produced")
	}
	if len(c.Devices) != 1 || c.Devices[0].Hostname != "gateway.local" {
		t.Errorf("devices wrong: %+v", c.Devices)
	}
	if len(c.NmapSummaries) != 1 {
		t.Errorf("nmap summaries lost")
	}
	if c.CrossRef == "" {
		t.Error("cross reference empty")
	}
}

func TestFormatForAISections(t *testing.T) {
	_, c := buildTestContext(t, false)
	formatted := c.FormatForAI()

	for _, want := range []string{
		"## Overview",
		"## Anomaly Signals",
		"## Top Talkers (raw stats)",
		"## Cross-Reference (nmap ↔ traffic)",
		"192.168.1.200",
	} {
		if !strings.Contains(formatted, want) {
			t.Errorf("AI format missing %q", want)
		}
	}
}

func TestNarrativesIncludedWhenPresent(t *testing.T) {
	_, c := buildTestContext(t, false)
	formatted := c.FormatForAI()
	if len(c.Summaries) > 0 && !strings.Contains(formatted, "What Each Device Is Doing") {
		t.Error("summaries section missing despite summaries existing")
	}
}

func TestDetectorFindingString(t *testing.T) {
	f := intel.Finding{IP: "1.2.3.4", Kind: intel.KScanner, Confidence: 0.85, Detail: "ports"}
	got := f.String()
	if !strings.Contains(got, "SCANNER") || !strings.Contains(got, "85%") {
		t.Errorf("finding render = %q", got)
	}
}

func TestLoadPacketsFromRealDB(t *testing.T) {
	db, _ := buildTestContext(t, false)
	packets, err := intel.LoadPackets(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 37 {
		t.Errorf("loaded %d packets, want 37", len(packets))
	}
	first := packets[0]
	if first.SrcIP != "192.168.1.200" || first.TCPdst == 0 {
		t.Errorf("first packet wrong: %+v", first)
	}
}
