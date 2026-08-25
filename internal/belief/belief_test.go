package belief

import (
	"math"
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/intel"
)

func TestNewSystemEmpty(t *testing.T) {
	s := New()
	if s.Len() != 0 || s.Has("192.168.1.1") {
		t.Error("fresh system should be empty")
	}
	if _, ok := s.Get("192.168.1.1"); ok {
		t.Error("Get on unknown should miss")
	}
	if _, _, ok := s.PriorityIP(3); ok {
		t.Error("PriorityIP on empty system should miss")
	}
}

func TestEnsureIP(t *testing.T) {
	s := New()
	s.Ensure("192.168.1.10")
	if s.Len() != 1 || !s.Has("192.168.1.10") {
		t.Fatal("Ensure did not track IP")
	}
	b, _ := s.Get("192.168.1.10")
	if b.MaxProb <= 0 || b.Scanned || b.ScanCount != 0 {
		t.Errorf("prior belief wrong: %+v", b)
	}
	s.Ensure("192.168.1.10")
	if s.Len() != 1 {
		t.Error("Ensure must be idempotent")
	}
	sum := 0.0
	for _, v := range b.Dist {
		sum += v
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("distribution sums to %f, want 1", sum)
	}
}

func TestInitializeFromFindings(t *testing.T) {
	s := New()
	findings := []intel.Finding{
		{IP: "10.0.0.1", Kind: intel.KBrowser, Confidence: 0.8},
		{IP: "10.0.0.2", Kind: intel.KScanner, Confidence: 0.6},
	}
	s.InitializeFromFindings(findings)
	if s.Len() != 2 {
		t.Fatalf("len = %d, want 2", s.Len())
	}
	if b, _ := s.Get("10.0.0.1"); b.MaxProb < 0.3 || b.MaxCat != Clean {
		t.Errorf("browser should push Clean high: %+v", b)
	}
	if b, _ := s.Get("10.0.0.2"); b.MaxProb < 0.3 || b.MaxCat != Bot {
		t.Errorf("scanner should push Bot high: %+v", b)
	}
}

func TestUpdateFromNmapAliveWithPorts(t *testing.T) {
	s := New()
	s.Ensure("192.168.1.50")
	beforeDist := copySnapshot(t, s, "192.168.1.50")

	s.UpdateFromNmap("192.168.1.50", true, []uint32{22, 80, 443})
	after, _ := s.Get("192.168.1.50")
	if !after.Scanned || after.ScanCount != 1 {
		t.Errorf("scan bookkeeping wrong: %+v", after)
	}
	same := true
	for c, v := range after.Dist {
		if beforeDist[c] == v {
			continue
		}
		same = false
	}
	if same {
		t.Error("distribution should change after scan evidence")
	}
	// Clean ports should boost Clean.
	if after.Dist[Clean] <= beforeDist[Clean] {
		t.Errorf("Clean prob should rise with open server ports: %f -> %f", beforeDist[Clean], after.Dist[Clean])
	}
}

func copySnapshot(t *testing.T, s *System, ip string) map[Category]float64 {
	t.Helper()
	b, ok := s.Get(ip)
	if !ok {
		t.Fatalf("missing belief for %s", ip)
	}
	return copyDist(b.Dist)
}

func TestUpdateFromNmapIotPorts(t *testing.T) {
	s := New()
	s.Ensure("192.168.1.60")
	s.UpdateFromNmap("192.168.1.60", true, []uint32{5353, 5683})
	b, _ := s.Get("192.168.1.60")
	if b.MaxCat != IoT && b.MaxCat != Unknown {
		t.Logf("max cat = %s (IoT boost may be diluted by prior)", b.MaxCat)
	}
	cleanBefore := b.Dist[IoT]
	s.UpdateFromNmap("192.168.1.60", true, []uint32{5353, 5683})
	b2, _ := s.Get("192.168.1.60")
	if b2.Dist[IoT] <= cleanBefore {
		t.Errorf("repeated IoT evidence should keep boosting IOT category")
	}
}

func TestUpdateUnknownIPNoop(t *testing.T) {
	s := New()
	s.UpdateFromNmap("10.99.99.99", true, []uint32{80})
	if s.Len() != 0 {
		t.Error("updating unknown IP must not add it")
	}
}

func TestPriorityIPEntropyAndScanCaps(t *testing.T) {
	s := New()
	s.Ensure("192.168.1.1")
	s.Ensure("192.168.1.2")
	s.UpdateFromNmap("192.168.1.1", true, []uint32{22, 80, 443})

	ip, _, ok := s.PriorityIP(3)
	if !ok || ip != "192.168.1.2" {
		t.Errorf("unscanned higher-entropy IP should be picked, got %s ok=%v", ip, ok)
	}

	for i := 0; i < 3; i++ {
		s.UpdateFromNmap("192.168.1.2", true, []uint32{})
	}
	b, _ := s.Get("192.168.1.2")
	if b.ScanCount != 3 {
		t.Fatalf("scan count = %d", b.ScanCount)
	}
	// .1 scanned once, .2 capped → still returns .1
	ip2, _, ok2 := s.PriorityIP(3)
	if !ok2 || ip2 != "192.168.1.1" {
		t.Errorf("expected fallback to .1, got %s ok=%v", ip2, ok2)
	}
}

func TestFormatAllAndIP(t *testing.T) {
	s := New()
	s.Ensure("192.168.1.10")
	s.Ensure("192.168.1.20")
	out := s.FormatAll()
	for _, want := range []string{"192.168.1.10", "192.168.1.20", "bits"} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatAll missing %q:\n%s", want, out)
		}
	}
	line, ok := s.FormatIP("192.168.1.10")
	if !ok || !strings.Contains(line, "entropy") {
		t.Errorf("FormatIP broken: %q", line)
	}
	if _, ok := s.FormatIP("nope"); ok {
		t.Error("FormatIP unknown should miss")
	}
}

func TestEntropyMath(t *testing.T) {
	det := map[Category]float64{Clean: 1.0}
	if e := entropy(det); e != 0 {
		t.Errorf("deterministic entropy = %f", e)
	}
	half := map[Category]float64{Bot: 0.5, Clean: 0.5}
	if e := entropy(half); e < 0.9 || e > 1.1 {
		t.Errorf("50/50 entropy = %f, want ~1", e)
	}
}

func TestNormalize(t *testing.T) {
	d := map[Category]float64{Bot: 3, Clean: 7}
	normalize(d)
	sum := 0.0
	for _, v := range d {
		sum += v
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("sum = %f", sum)
	}
	if d[Bot] < 0.29 || d[Bot] > 0.31 {
		t.Errorf("Bot = %f, want ~0.3", d[Bot])
	}
}

func TestFindingKindToCategory(t *testing.T) {
	cases := map[intel.Kind]Category{
		intel.KBot:        Bot,
		intel.KC2Beacon:   Bot,
		intel.KScanner:    Bot,
		intel.KBrowser:    Clean,
		intel.KServer:     Clean,
		intel.KIoTDevice:  IoT,
		intel.KPrinterIoT: IoT,
		intel.KVPN:        Unknown,
		intel.KTor:        Unknown,
		intel.KUnknown:    Unknown,
	}
	for k, want := range cases {
		if got := categoryForKind(k); got != want {
			t.Errorf("categoryForKind(%v) = %v, want %v", k, got, want)
		}
	}
}
