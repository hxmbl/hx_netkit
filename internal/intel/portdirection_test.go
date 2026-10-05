package intel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/store"
)

// buildHTTPSClient simulates an ordinary workstation: it opens sessions to
// several web servers (outbound to their service port) and receives their
// responses (inbound from that same service port).
func buildHTTPSClient(t *testing.T, ip string, servers, sessions int) *Profile {
	t.Helper()
	e := NewEngine()
	base := 1700000000.0
	n := 0
	for s := 0; s < servers; s++ {
		srv := fmt.Sprintf("93.184.%d.%d", s/256, s%256)
		for i := 0; i < sessions; i++ {
			sport := uint32(49152 + n%1000)
			e.Ingest(Packet{Epoch: base + float64(n)*0.5, SrcIP: ip, DstIP: srv,
				TCPsrc: sport, TCPdst: 443, FrameLen: 800})
			e.Ingest(Packet{Epoch: base + float64(n)*0.5 + 0.05, SrcIP: srv, DstIP: ip,
				TCPsrc: 443, TCPdst: sport, FrameLen: 1400})
			n++
		}
	}
	p := e.profiles[ip]
	p.finalize()
	return p
}

// buildHTTPSServer simulates a host that answers clients on port 443.
func buildHTTPSServer(t *testing.T, ip string, clients, sessions int) *Profile {
	t.Helper()
	e := NewEngine()
	base := 1700000000.0
	n := 0
	for c := 0; c < clients; c++ {
		cli := fmt.Sprintf("192.168.1.%d", 100+c)
		for i := 0; i < sessions; i++ {
			sport := uint32(50000 + n%1000)
			e.Ingest(Packet{Epoch: base + float64(n)*0.5, SrcIP: cli, DstIP: ip,
				TCPsrc: sport, TCPdst: 443, FrameLen: 600})
			e.Ingest(Packet{Epoch: base + float64(n)*0.5 + 0.05, SrcIP: ip, DstIP: cli,
				TCPsrc: 443, TCPdst: sport, FrameLen: 900})
			n++
		}
	}
	p := e.profiles[ip]
	p.finalize()
	return p
}

// Regression: port 443 is ordinary HTTPS, not a Tor port. A busy HTTPS client
// used to be reported as "Tor ports: 443" (55% confidence).
func TestDetectTorIgnoresPlainHTTPS(t *testing.T) {
	p := buildHTTPSClient(t, "192.168.1.50", 15, 10)
	if f := detectTor(p); f != nil {
		t.Errorf("HTTPS client misreported as Tor: %s", f.String())
	}
	if f := detectVPN(p); f != nil {
		t.Errorf("HTTPS client misreported as VPN: %s", f.String())
	}
	if p.ListenPorts[443] > 0 {
		t.Errorf("client recorded an inbound listen port: %v", p.ListenPorts)
	}
}

// Regression: inbound source ports are not "listening ports". An HTTPS client
// receives every response from port 443, so the old code reported it as a
// server that is "listening on: 443".
func TestDetectServerDoesNotLabelClientsAsServers(t *testing.T) {
	p := buildHTTPSClient(t, "192.168.1.50", 15, 10)
	if f := detectServer(p); f != nil {
		t.Errorf("HTTPS client misreported as a server: %s", f.String())
	}
	if n := p.PrivilegedListenCount(); n != 0 {
		t.Errorf("client claims %d privileged listen ports", n)
	}
}

// Regression: a real server reports its actual service port.
func TestDetectServerReportsRealListenPorts(t *testing.T) {
	p := buildHTTPSServer(t, "192.168.1.1", 12, 10)
	f := detectServer(p)
	if f == nil || f.Kind != KServer {
		t.Fatalf("expected server finding, got %+v", f)
	}
	if !strings.Contains(f.Detail, "listening on: 443") {
		t.Errorf("server should report its listen port: %s", f.Detail)
	}
	if n := p.UniqueClientCount(); n != 12 {
		t.Errorf("UniqueClientCount = %d, want 12", n)
	}
}

// Regression: every reply a server sends lands on a different ephemeral client
// port, so counting destination ports globally flagged every server with 20+
// clients as a port scanner.
func TestDetectScannerIgnoresServerReplyTraffic(t *testing.T) {
	p := buildHTTPSServer(t, "192.168.1.1", 40, 10)
	if p.MaxPortsOnPeer() >= 40 {
		t.Fatalf("per-peer port tracking broken: %d", p.MaxPortsOnPeer())
	}
	if f := detectScanner(p); f != nil {
		t.Errorf("server misreported as a scanner: %s", f.String())
	}
}

// ...while a real single-host port scan is still caught.
func TestDetectScannerStillCatchesMultiPortProbe(t *testing.T) {
	p := buildHTTPSServer(t, "192.168.1.1", 40, 10)
	e := NewEngine()
	for i := 0; i < 40; i++ {
		e.Ingest(Packet{Epoch: 1700000000 + float64(i), SrcIP: "192.168.1.77",
			DstIP: "192.168.1.1", TCPsrc: 40000 + uint32(i), TCPdst: uint32(1000 + i*3), FrameLen: 60})
	}
	q := e.profiles["192.168.1.77"]
	q.finalize()
	f := detectScanner(q)
	if f == nil || f.Kind != KScanner {
		t.Fatalf("multi-port probe not detected: %+v", f)
	}
	if !strings.Contains(f.Detail, "unique ports on one host") {
		t.Errorf("scanner indicator should be per-host: %s", f.Detail)
	}
	_ = p
}

// Regression: a Tor client dialing a relay on 9150 must still be detected.
func TestDetectTorStillCatchesRelayPort(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 30; i++ {
		e.Ingest(Packet{Epoch: 1700000000 + float64(i*30), SrcIP: "192.168.1.88",
			DstIP: "198.51.100.4", TCPsrc: uint32(40000 + i), TCPdst: 9150, FrameLen: 400})
	}
	p := e.profiles["192.168.1.88"]
	p.finalize()
	if f := detectTor(p); f == nil || f.Kind != KTor {
		t.Fatalf("Tor relay port missed: %+v", f)
	}
}

// Regression: the Tor/VPN port tables must contain only ports specific to
// those protocols. Any general-purpose web port in either table makes every
// HTTPS host match — the exact false positive these tables originally caused.
// (An earlier fix here wrongly added 8888, an unofficial alternate-HTTP port
// used by Jupyter/Fiddler, to torPorts.)
func TestTorAndVPNPortsExcludeWebPorts(t *testing.T) {
	webPorts := map[uint32]string{
		80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt",
		8888: "unofficial HTTP alt (Jupyter/Fiddler)", 3000: "dev HTTP",
	}
	for _, p := range torPorts {
		if name, ok := webPorts[p]; ok {
			t.Errorf("torPorts contains %d (%s) — every web host would match", p, name)
		}
	}
	for _, p := range vpnPorts {
		if name, ok := webPorts[p]; ok {
			t.Errorf("vpnPorts contains %d (%s) — every web host would match", p, name)
		}
	}
	for _, p := range []uint32{9001, 9030, 9150} { // Tor OR / Dir / SOCKS
		if !containsU32(torPorts, p) {
			t.Errorf("torPorts is missing the Tor port %d", p)
		}
	}
	for _, p := range []uint32{1194, 500, 4500, 51820} { // OpenVPN/IKE/NAT-T/WireGuard
		if !containsU32(vpnPorts, p) {
			t.Errorf("vpnPorts is missing the VPN port %d", p)
		}
	}
}

// Regression: BrowserSrcPortsMin is documented as "ephemeral source ports
// opened", i.e. ports the host ORIGINATES. SrcPorts holds the port the peer
// connected from, which for a client is a tiny fixed service set ({443}), so
// the signal could never fire for a browser and was instead credited to hosts
// receiving from many peers.
func TestDetectBrowserUsesOwnSourcePorts(t *testing.T) {
	const ip = "192.168.1.50"
	e := NewEngine()
	cdns := []string{"google.com", "gstatic.com", "cloudflare.com", "akamai.net",
		"facebook.com", "amazonaws.com", "bing.com", "fastly.net", "microsoft.com", "apple.com"}
	servers := []string{"142.250.72.14", "104.18.32.7", "151.101.1.69", "13.107.42.14",
		"23.45.112.9", "52.95.236.1", "34.120.7.9", "18.164.1.2", "99.84.108.22", "172.217.5.110"}
	base := 1700000000.0
	for i := 0; i < 300; i++ {
		srv := servers[i%len(servers)]
		sport := uint32(49152 + i*7%20000)
		e.Ingest(Packet{Epoch: base + float64(i)*0.3, SrcIP: ip, DstIP: srv,
			TCPsrc: sport, TCPdst: 443, FrameLen: 600, DNSQuery: cdns[i%len(cdns)]})
		e.Ingest(Packet{Epoch: base + float64(i)*0.3 + 0.1, SrcIP: srv, DstIP: ip,
			TCPsrc: 443, TCPdst: sport, FrameLen: 1200})
	}
	p := e.profiles[ip]
	p.finalize()
	if got := p.EphemeralOwnSrcPortCount(); got <= BrowserSrcPortsMin {
		t.Fatalf("own ephemeral source ports = %d, want > %d", got, BrowserSrcPortsMin)
	}
	f := detectBrowser(p)
	if f == nil {
		t.Fatal("a textbook HTTPS browser was not detected")
	}
	if !strings.Contains(f.Detail, "ephemeral source ports") {
		t.Errorf("browser should cite its ephemeral source ports: %s", f.Detail)
	}
}

// ...and the converse: a host that only RECEIVES must not accumulate
// "ephemeral source ports" out of its peers' ports.
func TestBrowserSignalNotCreditedToReceivingHosts(t *testing.T) {
	const ip = "192.168.1.60"
	e := NewEngine()
	for i := 0; i < 60; i++ { // 60 distinct peer source ports arriving at us
		e.Ingest(Packet{Epoch: 1700000000 + float64(i)*0.5, SrcIP: "192.168.1.9",
			DstIP: ip, TCPsrc: uint32(30000 + i), TCPdst: 6881, FrameLen: 400})
	}
	p := e.profiles[ip]
	p.finalize()
	if len(p.SrcPorts) < 25 {
		t.Skip("fixture did not produce distinct peer source ports")
	}
	if got := p.EphemeralOwnSrcPortCount(); got != 0 {
		t.Errorf("receiving host claims %d own ephemeral source ports, want 0", got)
	}
}

// Regression: one packet with an unusable timestamp (legacy NULL epoch, or a
// frame whose frame.time_epoch could not be parsed) used to be loaded as
// epoch 0, stretching the profile's duration to ~the capture's absolute time
// and destroying beacon detection.
func TestLoadPacketsSkipsUnusableEpochs(t *testing.T) {
	db, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// 40 perfectly regular 30s beacons.
	for i := 0; i <= 40; i++ {
		if err := db.InsertPacket(1700000000+float64(i)*30, "10.0.0.5", "198.51.100.1",
			int64(5000+i), 443, 0, 0, "", "", 100); err != nil {
			t.Fatal(err)
		}
	}
	// A legacy row with a NULL epoch.
	if _, err := db.Exec(`INSERT INTO packets (epoch, ip_src, ip_dst, frame_len) VALUES (NULL,'10.0.0.5','198.51.100.1',100)`); err != nil {
		t.Fatal(err)
	}

	packets, err := LoadPackets(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packets {
		if p.Epoch <= 0 {
			t.Fatalf("packet with unusable epoch leaked into the analysis: %+v", p)
		}
	}
	e := NewEngine()
	e.IngestBatch(packets)
	prof := e.Profiles()["10.0.0.5"]
	if prof == nil {
		t.Fatal("no profile built")
	}
	prof.finalize()
	if d := prof.Duration(); d > 2000 {
		t.Fatalf("duration inflated to %.0fs by an unusable epoch", d)
	}
	if f := detectBeacon(prof); f == nil {
		t.Error("regular 30s beacon no longer detected after a junk row")
	}
}
