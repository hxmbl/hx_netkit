package intel

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression (audit H3): serialized findings must carry the detector kind.
func TestFindingJSONHasKind(t *testing.T) {
	f := Finding{IP: "1.2.3.4", Kind: KC2Beacon, Confidence: 0.9, Detail: "d"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"type", "kind"} {
		if v, ok := m[key].(string); !ok || v != "C2_BEACON" {
			t.Errorf("%s = %v, want C2_BEACON (json: %s)", key, m[key], b)
		}
	}
	if pct, ok := m["confidence_pct"].(float64); !ok || int(pct) != 90 {
		t.Errorf("confidence_pct = %v, want 90", m["confidence_pct"])
	}
}

// Regression (audit L7): correlate output order is fully deterministic.
func TestFindingOrderDeterministic(t *testing.T) {
	run := func() string {
		e := NewEngine()
		// Two symmetric scanner IPs produce same-confidence findings.
		for i := 0; i < 30; i++ {
			e.Ingest(packet(1000+float64(i), "192.168.7.2", "192.168.7.1", uint32(2000+i), 60))
			e.Ingest(packet(1000+float64(i), "192.168.7.1", "192.168.7.2", uint32(3000+i), 60))
		}
		findings := e.Correlate(nil, false)
		var b strings.Builder
		for _, f := range findings {
			b.WriteString(f.String() + "\n")
		}
		return b.String()
	}
	if run() != run() {
		t.Error("correlate ordering unstable across identical runs")
	}
}

// Regression (audit L1): IPv6 loopback/link-local are internal addresses.
func TestIsPrivateIPv6(t *testing.T) {
	internal := []string{"::1", "fe80::1", "fc00::1", "fd12:3456::9", "::"}
	external := []string{"2001:db8::1", "2606:4700::1111"}
	for _, ip := range internal {
		if !IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%q) = false, want true", ip)
		}
	}
	for _, ip := range external {
		if IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%q) = true, want false", ip)
		}
	}
}

// Regression (audit L2): "hp" requires a standalone token.
func TestPrinterKeywordTokenMatch(t *testing.T) {
	const ip = "9.9.9.9"
	matching := []DeviceInfo{
		{IP: ip, Hostname: "HP LaserJet"},
		{IP: ip, Vendor: "hp"},
		{IP: ip, Hostname: "office-hp-printer"}, // hyphen splits tokens
	}
	notMatching := []DeviceInfo{
		{IP: ip, Hostname: "php-server"},
		{IP: ip, Vendor: "ShopMart"},
		{IP: ip, Hostname: "happy-device"},
	}
	p := finalizeCopy(makeTestProfile(ip)) // low packet rate contributes +0.2 like real captures
	for _, d := range matching {
		f := detectPrintersIoT(p, []DeviceInfo{d})
		if f == nil || f.Kind != KPrinterIoT {
			t.Errorf("printer missed for %+v", d)
		}
	}
	for _, d := range notMatching {
		f := detectPrintersIoT(p, []DeviceInfo{d})
		if f != nil && f.Kind == KPrinterIoT && strings.Contains(f.Detail, "printer detected") {
			t.Errorf("false printer detection for %+v", d)
		}
	}
}

// Regression (audit L6): narrative domain list is deterministic (top counts).
func TestNarrativeContactsDeterministic(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 20; i++ {
		pkt := packet(1000+float64(i), "192.168.50.1", "93.184.216.34", 443, 1400)
		switch {
		case i < 10:
			pkt.DNSQuery = "alpha.example.com"
		case i < 15:
			pkt.DNSQuery = "beta.example.org"
		default:
			pkt.DNSQuery = "gamma.example.net"
		}
		e.Ingest(pkt)
	}
	findings := e.Correlate(nil, false)
	sums := GenerateNarratives(e.Profiles(), nil, findings)
	var narrative string
	for _, s := range sums {
		if s.IP == "192.168.50.1" {
			narrative = s.Narrative
		}
	}
	if !strings.Contains(narrative, "Primarily contacts example.com") {
		t.Errorf("narrative should lead with the most-queried domain:\n%s", narrative)
	}
	sums2 := GenerateNarratives(e.Profiles(), nil, findings)
	var n2 string
	for _, s := range sums2 {
		if s.IP == "192.168.50.1" {
			n2 = s.Narrative
		}
	}
	if narrative != n2 {
		t.Errorf("narrative unstable across runs:\n%s\n---\n%s", narrative, n2)
	}
}

// Regression (audit L4): window trimming keeps the logical view correct
// across many evictions without re-slicing every packet.
func TestRealtimeWindowCompactionStable(t *testing.T) {
	r := NewRealtime(5, false)
	clock := 1000.0
	r.SetClock(func() float64 { return clock })
	for i := 0; i < 500; i++ {
		clock += 1
		r.Ingest(packet(clock, "10.2.0.1", "10.2.0.2", 80, 60))
	}
	win := r.WindowPackets()
	cutoff := clock - 5
	for _, p := range win {
		if p.Epoch <= cutoff-1 {
			t.Fatalf("stale packet survived eviction: epoch %f cutoff %f", p.Epoch, cutoff)
		}
	}
}
