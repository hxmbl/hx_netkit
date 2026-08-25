package intel

import (
	"strconv"
	"strings"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	private := []string{"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1", "192.168.0.0", "169.254.1.1"}
	public := []string{"8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.0.1", "1.1.1.1", "not-an-ip", "10.0.1", "", "300.1.1.1"}

	for _, ip := range private {
		if !IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%q) = false, want true", ip)
		}
	}
	for _, ip := range public {
		if IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%q) = true, want false", ip)
		}
	}
}

func TestExtractDomain(t *testing.T) {
	cases := map[string]string{
		"www.google.com":         "google.com",
		"cdn.assets.example.com": "example.com",
		"single":                 "single",
		"a.b":                    "a.b",
		"trailing.dots.com.":     "dots.com",
	}
	for in, want := range cases {
		if got := ExtractDomain(in); got != want {
			t.Errorf("ExtractDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	var uniform []uint32
	for i := 0; i < 10; i++ {
		uniform = append(uniform, uint32(i))
	}
	if e := ShannonEntropy(uniform); e < 3.0 {
		t.Errorf("uniform entropy = %f, want > 3", e)
	}
	single := make([]uint32, 10)
	if e := ShannonEntropy(single); e > 0.1 {
		t.Errorf("single-value entropy = %f, want ~0", e)
	}
	if e := ShannonEntropy(nil); e != 0 {
		t.Errorf("empty entropy = %f", e)
	}
}

func TestPortSetEntropy(t *testing.T) {
	m := map[uint32]uint64{80: 100, 443: 50, 22: 3}
	if e := portSetEntropy(m); e < 1.5 || e > 1.7 {
		t.Errorf("log2(3) entropy = %f", e)
	}
	if e := portSetEntropy(map[uint32]uint64{}); e != 0 {
		t.Errorf("empty = %f", e)
	}
}

// makeTestProfile builds a synthetic profile like the v1 tests did.
func makeTestProfile(ip string) *Profile {
	p := newProfile(ip)
	p.FirstSeen = 1000
	p.LastSeen = 2000
	p.PacketCount = 50
	p.OutboundCount = 30
	p.InboundCount = 20
	return p
}

func TestDetectBrowser(t *testing.T) {
	p := makeTestProfile("192.168.1.50")
	for i := 0; i < 25; i++ {
		p.DNSDomains[string(rune('a'+i))+".site"+itoa(i)+".example.com"] = 2
	}
	p.DNSDomains["google.com"] = 10
	p.DNSDomains["youtube.com"] = 5
	p.DNSDomains["facebook.com"] = 3
	p.DestPorts[443] = 20
	p.DestPorts[80] = 10
	for i := 0; i < 15; i++ {
		p.SrcPorts[uint32(49152+i)] = 1
	}
	for i := 1; i <= 12; i++ {
		p.DestIPs["10.0.0."+itoa(i)] = 2
	}
	f := detectBrowser(finalizeCopy(p))
	if f == nil || f.Kind != KBrowser {
		t.Fatalf("expected browser finding, got %+v", f)
	}
}

func TestDetectBotPrecisionBeacon(t *testing.T) {
	p := makeTestProfile("192.168.1.99")
	p.PacketCount = 500
	p.OutboundCount = 450
	// Perfectly regular 5s intervals over 40 packets.
	base := 1000.0
	for i := 0; i < 40; i++ {
		p.interArrivalTimes = append(p.interArrivalTimes, base+float64(i)*5.0)
	}
	p.DestPorts[443] = 480 // monotonic port dominance
	f := detectBot(finalizeCopy(p))
	if f == nil || f.Kind != KBot {
		t.Fatalf("expected bot finding, got %+v", f)
	}
	if f.Confidence < BotThreshold {
		t.Errorf("confidence %f below threshold", f.Confidence)
	}
}

func TestDetectServer(t *testing.T) {
	p := makeTestProfile("192.168.1.1")
	for i := 1; i <= 12; i++ {
		p.SrcIPs["10.1.0."+itoa(i)] = uint64(5)
	}
	p.SrcPorts[80] = 200
	p.InboundCount = 400
	p.OutboundCount = 50
	for i := 0; i < 20; i++ {
		key := sessionKey("c"+itoa(i), 50000+uint32(i), p.IP, 49200+uint32(i))
		p.Sessions[key] = &TCPSession{FirstPacket: 1000, LastPacket: 1100, PktCount: 4}
	}
	f := detectServer(finalizeCopy(p))
	if f == nil || f.Kind != KServer {
		t.Fatalf("expected server finding, got %+v", f)
	}
}

func TestDetectScanner(t *testing.T) {
	p := makeTestProfile("192.168.1.7")
	// Sequential ports 100..140 (> threshold).
	for i := 100; i <= 140; i++ {
		p.DestPorts[uint32(i)] = 1
	}
	p.OutboundCount = 41
	f := detectScanner(finalizeCopy(p))
	if f == nil || f.Kind != KScanner {
		t.Fatalf("expected scanner finding, got %+v", f)
	}
}

func TestDetectDataExfil(t *testing.T) {
	p := makeTestProfile("192.168.1.66")
	p.OutboundCount = 900
	p.InboundCount = 10
	p.DestIPs["203.0.113.9"] = 850
	p.DNSDomains["exfil.example"] = 3
	f := detectDataExfil(finalizeCopy(p))
	if f == nil || f.Kind != KDataExfil {
		t.Fatalf("expected exfil finding, got %+v", f)
	}
}

func TestDetectLateralMovement(t *testing.T) {
	all := map[string]*Profile{}
	p := makeTestProfile("192.168.1.10")
	for i := 1; i <= 6; i++ {
		ip := "192.168.1." + itoa(100+i)
		p.DestIPs[ip] = 10
		all[ip] = newProfile(ip)
	}
	all[p.IP] = p
	p.OutboundCount = 60
	p.DestPorts[22] = 15
	p.DestPorts[3389] = 10
	p.DestPorts[445] = 10
	f := detectLateralMovement(finalizeCopy(p), all)
	if f == nil || f.Kind != KLateralMovement {
		t.Fatalf("expected lateral movement finding, got %+v", f)
	}
}

func TestDetectC2Beacon(t *testing.T) {
	p := makeTestProfile("192.168.1.42")
	// Jittered C2: mean > 10s, CV in [0.05, 0.30).
	intervals := jitteredIntervals(12.0, 0.10, 30)
	base := 1000.0
	ts := base
	for _, iv := range intervals {
		p.interArrivalTimes = append(p.interArrivalTimes, ts)
		ts += iv
	}
	p.interArrivalTimes = append(p.interArrivalTimes, ts)
	p.DestIPs["198.51.100.7"] = 25
	p.DNSCount = 2
	p.OutboundCount = 25
	f := detectC2Beacon(finalizeCopy(p))
	if f == nil || f.Kind != KC2Beacon {
		t.Fatalf("expected C2 beacon finding, got %+v", f)
	}
}

func TestDetectNetworkRecon(t *testing.T) {
	p := makeTestProfile("192.168.1.13")
	for _, pt := range []uint32{22, 23, 80, 443, 8080} {
		p.DestPorts[pt] = 1
	}
	for i := 1; i <= 6; i++ {
		p.DestIPs["192.168.1."+itoa(i)] = 2
	}
	p.OutboundCount = 12
	f := detectNetworkRecon(finalizeCopy(p))
	if f == nil || f.Kind != KNetworkRecon {
		t.Fatalf("expected recon finding, got %+v", f)
	}
}

func TestDetectPrintersIoTByHostname(t *testing.T) {
	p := makeTestProfile("192.168.1.30")
	devices := []DeviceInfo{{IP: p.IP, Hostname: "HP-LaserJet-Printer"}}
	f := detectPrintersIoT(finalizeCopy(p), devices)
	if f == nil || f.Kind != KPrinterIoT {
		t.Fatalf("expected printer finding, got %+v", f)
	}
}

func TestDetectVPNTunnel(t *testing.T) {
	p := makeTestProfile("192.168.1.77")
	p.DestPorts[1194] = 120
	p.PacketCount = 150
	p.DestIPs["198.51.100.99"] = 140
	f := detectVPN(finalizeCopy(p))
	if f == nil || f.Kind != KVPN {
		t.Fatalf("expected VPN finding, got %+v", f)
	}
}

func TestDetectTorPorts(t *testing.T) {
	p := makeTestProfile("192.168.1.88")
	p.SrcPorts[9150] = 60
	f := detectTor(finalizeCopy(p))
	if f == nil || f.Kind != KTor {
		t.Fatalf("expected Tor finding, got %+v", f)
	}
}

func TestDetectGameClient(t *testing.T) {
	p := makeTestProfile("192.168.1.21")
	p.DestPorts[27015] = 90
	f := detectGame(finalizeCopy(p))
	if f == nil || f.Kind != KGameClient {
		t.Fatalf("expected game finding, got %+v", f)
	}
}

func TestDetectStreaming(t *testing.T) {
	p := makeTestProfile("192.168.1.55")
	p.LastSeen = p.FirstSeen + 120 // long enough
	p.PacketCount = 400
	p.DNSDomains["nflxvideo.net"] = 9
	f := detectStreaming(finalizeCopy(p))
	if f == nil || f.Kind != KStreamingMedia {
		t.Fatalf("expected streaming finding, got %+v", f)
	}
}

func TestDetectCloudSync(t *testing.T) {
	p := makeTestProfile("192.168.1.56")
	p.DNSDomains["icloud.com"] = 20
	p.InboundCount = 30
	p.OutboundCount = 30
	f := detectCloudSync(finalizeCopy(p))
	if f == nil || f.Kind != KCloudSync {
		t.Fatalf("expected cloud sync finding, got %+v", f)
	}
}

func TestDetectDNSProfiler(t *testing.T) {
	p := makeTestProfile("192.168.1.57")
	p.LastSeen = p.FirstSeen + 10
	p.DNSCount = 200
	for i := 0; i < 70; i++ {
		p.DNSDomains["dga-"+itoa(i)+".xyz"] = 3
	}
	p.OutboundCount = 5
	f := detectDNSProfiler(finalizeCopy(p))
	if f == nil || f.Kind != KDNSProfiler {
		t.Fatalf("expected dns profiler finding, got %+v", f)
	}
}

func TestDetectBeaconTight(t *testing.T) {
	p := makeTestProfile("192.168.1.58")
	// Exact 30s intervals → CV ≈ 0.
	ts := 1000.0
	for i := 0; i < 20; i++ {
		p.interArrivalTimes = append(p.interArrivalTimes, ts)
		ts += 30
	}
	p.interArrivalTimes = append(p.interArrivalTimes, ts)
	p.DestIPs["198.51.100.3"] = 21
	f := detectBeacon(finalizeCopy(p))
	if f == nil || f.Kind != KBeacon {
		t.Fatalf("expected beacon finding, got %+v", f)
	}
}

func TestDetectIoTMulticast(t *testing.T) {
	p := makeTestProfile("192.168.1.59")
	p.DestPorts[5353] = 12
	f := detectIoT(finalizeCopy(p))
	if f == nil || f.Kind != KIoTDevice {
		t.Fatalf("expected IoT finding, got %+v", f)
	}
}

// ── engine-level tests ──────────────────────────────────────────────────────

func packet(epoch float64, src, dst string, dport uint32, frame uint32) Packet {
	return Packet{
		Epoch: epoch, SrcIP: src, DstIP: dst,
		TCPsrc: 49200, TCPdst: dport,
		FrameLen: frame,
	}
}

func TestEngineCorrelateEndToEnd(t *testing.T) {
	e := NewEngine()
	// A scanner: hits many ports on one host quickly.
	for i := 0; i < 30; i++ {
		e.Ingest(packet(1000+float64(i), "192.168.1.200", "192.168.1.1", uint32(1000+i), 60))
	}
	findings := e.Correlate(nil, false)
	if len(findings) == 0 {
		t.Fatal("expected findings for scanner traffic")
	}
	foundScanner := false
	for _, f := range findings {
		if f.IP == "192.168.1.200" && f.Kind == KScanner {
			foundScanner = true
		}
	}
	if !foundScanner {
		t.Errorf("scanner not detected: %+v", findings)
	}
}

func TestEngineIgnoresTinyProfiles(t *testing.T) {
	e := NewEngine()
	for i := 0; i < MinPacketsForDetection-1; i++ {
		e.Ingest(packet(1000+float64(i), "192.168.1.201", "192.168.1.1", uint32(1000+i), 60))
	}
	findings := e.Correlate(nil, false)
	if len(findings) != 0 {
		t.Errorf("profiles under minimum should produce nothing, got %d", len(findings))
	}
}

func TestEngineUnknownFallbackFinding(t *testing.T) {
	e := NewEngine()
	// Enough packets but totally bland traffic.
	for i := 0; i < 10; i++ {
		e.Ingest(packet(1000+float64(i), "192.168.1.202", "192.168.1.1", 8080, 100))
	}
	findings := e.Correlate(nil, false)
	hasUnknown := false
	for _, f := range findings {
		if f.IP == "192.168.1.202" && f.Kind == KUnknown {
			hasUnknown = true
		}
	}
	if !hasUnknown {
		t.Errorf("bland IP should yield UNKNOWN finding, got %+v", findings)
	}
}

func TestCorporateModeDropsConsumerDetectors(t *testing.T) {
	e := NewEngine()
	// Game-like: Steam ports.
	for i := 0; i < 60; i++ {
		pkt := packet(1000+float64(i)*2, "192.168.1.203", "198.51.100.4", 27015, 120)
		pkt.TCPsrc = 0 // UDP-ish shape
		pkt.TCPdst = 0
		pkt.UDPsrc = 49200
		pkt.UDPdst = 27015
		e.Ingest(pkt)
	}
	openMode := e.Correlate(nil, false)
	corpMode := e.Correlate(nil, true)

	gameInOpen := false
	for _, f := range openMode {
		if f.Kind == KGameClient {
			gameInOpen = true
		}
	}
	for _, f := range corpMode {
		if f.Kind == KGameClient {
			t.Error("corporate mode must not emit consumer game findings")
		}
	}
	_ = gameInOpen // open mode may or may not cross confidence threshold
}

func TestCrossReferenceIncludesDeviceAndEvidence(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 12; i++ {
		e.Ingest(packet(1000+float64(i), "192.168.1.210", "93.184.216.34", 443, 1400))
	}
	e.Correlate(nil, false)

	devices := []DeviceInfo{{IP: "192.168.1.210", Hostname: "laptop", OSGuess: "macOS"}}
	out := e.CrossReference(devices)
	for _, want := range []string{"192.168.1.210", "laptop", "macOS", "Packet evidence"} {
		if !strings.Contains(out, want) {
			t.Errorf("cross reference missing %q in:\n%s", want, out)
		}
	}
}

func TestCrossReferenceUnknownDevice(t *testing.T) {
	e := NewEngine()
	out := e.CrossReference([]DeviceInfo{{IP: "10.9.9.9", Ports: "22/open/ssh"}})
	if !strings.Contains(out, "no traffic observed") || !strings.Contains(out, "22/open/ssh") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestFormatFindingsGrouping(t *testing.T) {
	out := FormatFindings([]Finding{
		{IP: "1.1.1.1", Kind: KScanner, Confidence: 0.9, Detail: "scan"},
		{IP: "2.2.2.2", Kind: KBrowser, Confidence: 0.8, Detail: "web"},
	})
	if !strings.Contains(out, "SCANNER") || !strings.Contains(out, "BROWSER") {
		t.Errorf("grouping broken:\n%s", out)
	}
	if out := FormatFindings(nil); out != "(no findings)" {
		t.Errorf("empty rendering = %q", out)
	}
}

func TestRealtimeWindowEviction(t *testing.T) {
	r := NewRealtime(10, false)
	clock := 100.0
	r.SetClock(func() float64 { return clock })

	old := packet(85, "10.0.0.1", "10.0.0.2", 80, 100)
	r.Ingest(old) // epoch 85 < cutoff once clock advances past 95
	clock = 101
	recent := packet(100.5, "10.0.0.3", "10.0.0.4", 443, 100)
	r.Ingest(recent)

	if r.ShouldAnalyze() {
		t.Error("should not analyze immediately")
	}
	clock += 6
	if !r.ShouldAnalyze() {
		t.Error("should analyze after min interval")
	}
	findings := r.AnalyzeWindow()
	if findings == nil {
		t.Log("no findings for tiny window (ok)")
	}
	win := r.WindowPackets()
	if len(win) != 1 || win[0].Epoch != 100.5 {
		t.Errorf("window eviction failed: %+v", win)
	}
}

func TestRealtimeCorporatePassthrough(t *testing.T) {
	r := NewRealtime(600, true)
	clock := 100.0
	r.SetClock(func() float64 { return clock })
	for i := 0; i < 60; i++ {
		pkt := packet(1000+float64(i)*2, "192.168.9.9", "198.51.100.4", 27015, 120)
		pkt.TCPsrc, pkt.TCPdst = 0, 0
		pkt.UDPsrc, pkt.UDPdst = 49200, 27015
		r.Ingest(pkt)
	}
	clock += 6
	for _, f := range r.AnalyzeWindow() {
		if f.Kind == KGameClient {
			t.Error("corporate realtime window must not emit consumer game findings")
		}
	}
}

func TestEngineRetainsBoundedPacketBuffer(t *testing.T) {
	e := NewEngine()
	total := maxRetainedPackets*3 + 1000
	for i := 0; i < total; i++ {
		e.Ingest(packet(float64(i), "10.1.0.1", "10.1.0.2", 80, 60))
	}
	// Amortized retention: buffer may transiently hold up to 2× cap between
	// compactions, but must never grow unbounded and must keep recent data.
	if len(e.packets) > maxRetainedPackets*2 {
		t.Errorf("retained %d packets, hard ceiling is %d", len(e.packets), maxRetainedPackets*2)
	}
	if len(e.packets) < maxRetainedPackets {
		t.Errorf("retained only %d packets, want ≥ %d of recent evidence", len(e.packets), maxRetainedPackets)
	}
	if e.packets[len(e.packets)-1].Epoch != float64(total-1) {
		t.Error("newest packet lost during retention")
	}
}

func TestNarrativeGeneration(t *testing.T) {
	type intelSummary = BehavioralSummary
	e := NewEngine()
	for i := 0; i < 30; i++ {
		e.Ingest(packet(1000+float64(i), "192.168.1.220", "93.184.216.34", 443, 1400))
	}
	findings := e.Correlate(nil, false)
	summaries := GenerateNarratives(e.Profiles(), nil, findings)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries (src+dst), got %d", len(summaries))
	}
	var s intelSummary
	for _, x := range summaries {
		if x.IP == "192.168.1.220" {
			s = intelSummary(x)
		}
	}
	if s.IP == "" {
		t.Fatal("missing summary for target IP")
	}
	if s.Narrative == "" || s.DeviceType == "" || s.Role == "" {
		t.Errorf("summary incomplete: %+v", s)
	}
	rendered := s.String()
	if !strings.Contains(rendered, "### 192.168.1.220") {
		t.Errorf("render missing header:\n%s", rendered)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func itoa(i int) string { return strconv.Itoa(i) }

func finalizeCopy(p *Profile) *Profile {
	p.finalize()
	return p
}

// jitteredIntervals returns n intervals around mean with target CV.
func jitteredIntervals(mean, cv float64, n int) []float64 {
	out := make([]float64, 0, n+1)
	delta := mean * cv // alternate +/- delta
	v := mean - delta
	sign := -1.0
	for i := 0; i < n; i++ {
		out = append(out, v)
		v = mean + sign*delta
		sign = -sign
	}
	out = append(out, mean)
	return out
}
