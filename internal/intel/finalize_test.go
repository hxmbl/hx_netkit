package intel

import "testing"

// finalize() must be idempotent: Correlate() can be called more than once on
// the same engine (batch + realtime analyses), and the old version appended
// into per-profile slices, so a second call duplicated them.
func TestFinalizeIsIdempotent(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 40; i++ {
		e.Ingest(packet(1000+float64(i), "192.168.1.5", "93.184.216.34", 443, 900))
	}
	p := e.profiles["192.168.1.5"]
	p.finalize()
	firstEntropy, firstBurst, firstConns := p.DestPortEntropy, p.BurstScore, p.UniqueConnections
	for i := 0; i < 3; i++ {
		p.finalize()
		if p.DestPortEntropy != firstEntropy || p.BurstScore != firstBurst || p.UniqueConnections != firstConns {
			t.Fatalf("finalize %d changed state: entropy %v->%v burst %v->%v conns %v->%v",
				i+1, firstEntropy, p.DestPortEntropy, firstBurst, p.BurstScore,
				firstConns, p.UniqueConnections)
		}
	}
}

// Correlate() twice must yield identical findings (no accumulated state).
func TestRepeatedCorrelateIsStable(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 60; i++ {
		e.Ingest(packet(1000+float64(i), "192.168.1.77", "192.168.1.9", uint32(1000+i), 60))
	}
	a := e.Correlate(nil, false)
	b := e.Correlate(nil, false)
	if len(a) != len(b) {
		t.Fatalf("finding count changed between runs: %d then %d", len(a), len(b))
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			t.Errorf("finding %d changed:\n%s\n%s", i, a[i].String(), b[i].String())
		}
	}
}
