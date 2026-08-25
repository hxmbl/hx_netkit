package intel

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func nowUnix() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// Engine ingests packets into per-IP profiles and runs detectors.
type Engine struct {
	profiles map[string]*Profile
	packets  []Packet
}

// NewEngine creates an empty correlation engine.
func NewEngine() *Engine {
	return &Engine{profiles: map[string]*Profile{}}
}

// Ingest adds one packet, feeding both the source and destination profiles.
func (e *Engine) Ingest(pkt Packet) {
	if pkt.SrcIP != "" {
		p := e.ensure(pkt.SrcIP)
		p.ingest(pkt)
	}
	if pkt.DstIP != "" && pkt.DstIP != pkt.SrcIP {
		p := e.ensure(pkt.DstIP)
		p.ingest(pkt)
	}
	e.packets = append(e.packets, pkt)

	// Amortized retention: once the buffer doubles past the cap, keep only
	// the newest half-cap window of evidence.
	if len(e.packets) >= maxRetainedPackets*2 {
		e.packets = append([]Packet(nil), e.packets[len(e.packets)-maxRetainedPackets:]...)
	}
}

// IngestBatch ingests a stream of packets.
func (e *Engine) IngestBatch(pkts []Packet) {
	for _, p := range pkts {
		e.Ingest(p)
	}
}

func (e *Engine) ensure(ip string) *Profile {
	p, ok := e.profiles[ip]
	if !ok {
		p = newProfile(ip)
		e.profiles[ip] = p
	}
	return p
}

func (e *Engine) finalizeAll() {
	for _, p := range e.profiles {
		p.finalize()
	}
}

// Profiles returns the live profile map (call Finalize/Correlate first for stats).
func (e *Engine) Profiles() map[string]*Profile { return e.profiles }

// PacketCount returns the number of ingested packets.
func (e *Engine) PacketCount() int { return len(e.packets) }

// Packets exposes the packet buffer for cross-referencing.
func (e *Engine) Packets() []Packet { return e.packets }

// Correlate finalizes profiles and runs all detectors. corporateMode drops
// consumer-focused detectors (streaming, cloud sync, gaming).
func (e *Engine) Correlate(devices []DeviceInfo, corporateMode bool) []Finding {
	e.finalizeAll()

	var findings []Finding
	allProfiles := make(map[string]*Profile, len(e.profiles))
	for ip, p := range e.profiles {
		allProfiles[ip] = p
	}

	for _, profile := range e.profiles {
		if profile.PacketCount < MinPacketsForDetection {
			continue
		}
		var ipFindings []*Finding

		baseDetectors := []func(*Profile) *Finding{
			detectBrowser,
			detectBot,
			detectServer,
			detectIoT,
			detectDNSProfiler,
			detectBeacon,
			detectScanner,
			detectVPN,
			detectTor,
		}
		consumerDetectors := []func(*Profile) *Finding{
			detectStreaming,
			detectCloudSync,
			detectGame,
		}

		for _, d := range baseDetectors {
			if f := d(profile); f != nil {
				ipFindings = append(ipFindings, f)
			}
		}
		if !corporateMode {
			for _, d := range consumerDetectors {
				if f := d(profile); f != nil {
					ipFindings = append(ipFindings, f)
				}
			}
		}

		if f := detectLateralMovement(profile, allProfiles); f != nil {
			ipFindings = append(ipFindings, f)
		}
		if f := detectDataExfil(profile); f != nil {
			ipFindings = append(ipFindings, f)
		}
		if f := detectC2Beacon(profile); f != nil {
			ipFindings = append(ipFindings, f)
		}
		if f := detectNetworkRecon(profile); f != nil {
			ipFindings = append(ipFindings, f)
		}
		if f := detectPrintersIoT(profile, devices); f != nil {
			ipFindings = append(ipFindings, f)
		}

		if len(ipFindings) == 0 {
			ipFindings = append(ipFindings, &Finding{
				IP:         profile.IP,
				Kind:       KUnknown,
				Confidence: 0,
				Detail: fmt.Sprintf("%d pkts, %d out, %d in, %d dns, %d domains",
					profile.PacketCount, profile.OutboundCount,
					profile.InboundCount, profile.DNSCount, len(profile.DNSDomains)),
				Indicators: nil,
			})
		}

		for _, f := range ipFindings {
			findings = append(findings, *f)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return a.Kind < b.Kind
	})
	return findings
}

// CrossReference merges nmap device knowledge with observed traffic.
func (e *Engine) CrossReference(devices []DeviceInfo) string {
	var lines []string

	for _, dev := range devices {
		hostname := dev.Hostname
		if hostname == "" {
			hostname = "unknown"
		}
		osStr := dev.OSGuess
		if osStr == "" {
			osStr = "OS unknown"
		}
		vendor := dev.Vendor
		if vendor == "" {
			vendor = "unknown vendor"
		}

		profile, ok := e.profiles[dev.IP]
		if !ok {
			lines = append(lines, fmt.Sprintf(
				"Device at %s (%s, %s, %s) — no traffic observed in capture",
				dev.IP, hostname, osStr, vendor))
			if dev.Ports != "" {
				lines = append(lines, "  Open ports: "+dev.Ports)
			}
			continue
		}

		duration := profile.Duration()
		pps := 0.0
		if duration > 0 {
			pps = float64(profile.PacketCount) / duration
		}

		topDomains := formatCounts(profile.TopDNS(5))
		topPorts := formatPortCounts(profile.TopDestPorts(5))

		type sc struct {
			ip string
			c  uint64
		}
		srcs := make([]sc, 0, len(profile.SrcIPs))
		for ip, c := range profile.SrcIPs {
			srcs = append(srcs, sc{ip, c})
		}
		sort.Slice(srcs, func(i, j int) bool {
			if srcs[i].c != srcs[j].c {
				return srcs[i].c > srcs[j].c
			}
			return srcs[i].ip < srcs[j].ip
		})
		if len(srcs) > 3 {
			srcs = srcs[:3]
		}
		topSrcs := make([]string, len(srcs))
		for i, s := range srcs {
			topSrcs[i] = fmt.Sprintf("%s(%d)", s.ip, s.c)
		}

		lines = append(lines, fmt.Sprintf(
			"Device at %s (%s, %s, %s) — %d packets over %.1fs (%.1f pps), %d out / %d in, %d TCP, %d UDP\n"+
				"  DNS: %d domains [%s]\n"+
				"  Dest ports: [%s]\n"+
				"  Top sources: [%s]",
			dev.IP, hostname, osStr, vendor,
			profile.PacketCount, duration, pps, profile.OutboundCount, profile.InboundCount,
			profile.TCPCount, profile.UDPCount,
			len(profile.DNSDomains), topDomains, topPorts, strings.Join(topSrcs, ", "),
		))

		// Sample packet evidence.
		var samples []Packet
		for _, pkt := range e.packets {
			if pkt.SrcIP == dev.IP || pkt.DstIP == dev.IP {
				samples = append(samples, pkt)
				if len(samples) == 5 {
					break
				}
			}
		}
		if len(samples) > 0 {
			pl := make([]string, len(samples))
			for i, p := range samples {
				port := p.dstPort()
				proto := "?"
				switch {
				case p.hasTCP():
					proto = "TCP"
				case p.hasUDP():
					proto = "UDP"
				}
				dns := ""
				if p.DNSQuery != "" {
					dns = " dns=" + p.DNSQuery
				}
				pl[i] = fmt.Sprintf("    %s → %s:%d/%s%s", orQ(p.SrcIP), orQ(p.DstIP), port, proto, dns)
			}
			lines = append(lines, "  Packet evidence:\n"+strings.Join(pl, "\n"))
		}

		// Top peer connections with port sets.
		dests := make([]sc, 0, len(profile.DestIPs))
		for ip, c := range profile.DestIPs {
			dests = append(dests, sc{ip, c})
		}
		sort.Slice(dests, func(i, j int) bool {
			if dests[i].c != dests[j].c {
				return dests[i].c > dests[j].c
			}
			return dests[i].ip < dests[j].ip
		})
		if len(dests) > 3 {
			dests = dests[:3]
		}
		if len(dests) > 0 {
			peers := make([]string, 0, len(dests))
			for _, d := range dests {
				portSet := map[uint32]bool{}
				for _, pkt := range e.packets {
					if pkt.SrcIP == dev.IP && pkt.DstIP == d.ip {
						if pt := pkt.dstPort(); pt > 0 {
							portSet[pt] = true
						}
					}
				}
				ports := make([]string, 0, len(portSet))
				for pt := range portSet {
					ports = append(ports, fmt.Sprint(pt))
				}
				sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
				peers = append(peers, fmt.Sprintf("    %s (%d pkts, ports: %s)", d.ip, d.c, strings.Join(ports, ", ")))
			}
			lines = append(lines, "  Top connections:\n"+strings.Join(peers, "\n"))
		}

		var openTCP []string
		for port := range profile.SrcPorts {
			if port < PrivilegedPortMax {
				openTCP = append(openTCP, fmt.Sprint(port))
			}
		}
		sort.Strings(openTCP)
		if len(openTCP) > 0 {
			lines = append(lines, "  Listening on: "+strings.Join(openTCP, ", "))
		}
		if clients := len(profile.SrcIPs); clients > 3 {
			lines = append(lines, fmt.Sprintf("  Serving %d unique clients", clients))
		}
	}

	return strings.Join(lines, "\n")
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func formatCounts(dcs []DomainCount) string {
	parts := make([]string, len(dcs))
	for i, d := range dcs {
		parts[i] = fmt.Sprintf("%s(%d)", d.Domain, d.Count)
	}
	return strings.Join(parts, ", ")
}

func formatPortCounts(pcs []PortCount) string {
	parts := make([]string, len(pcs))
	for i, pcse := range pcs {
		parts[i] = fmt.Sprintf("%d/%d", pcse.Port, pcse.Count)
	}
	return strings.Join(parts, ", ")
}

// PrintFindings renders grouped findings to a writer-friendly string.
// Group order matches severity presentation used by the CLI.
func FormatFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "(no findings)"
	}
	order := []Kind{
		KServer, KBrowser, KBot, KScanner, KBeacon, KC2Beacon,
		KLateralMovement, KDataExfil, KNetworkRecon, KTor, KVPN,
		KIoTDevice, KPrinterIoT, KIoTCoordinator,
		KDNSProfiler, KStreamingMedia, KCloudSync, KGameClient, KUnknown,
	}

	byKind := map[Kind][]Finding{}
	for _, f := range findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}

	var b strings.Builder
	for _, k := range order {
		group, ok := byKind[k]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "\n── %s (%d) ──\n", k, len(group))
		for _, f := range group {
			fmt.Fprintf(&b, "  %-16s [%d%%] %s\n", f.IP, f.ConfidencePct(), f.Detail)
			for j, ind := range f.Indicators {
				if j == 3 {
					break
				}
				fmt.Fprintf(&b, "  %-16s      → %s\n", "", ind)
			}
		}
	}
	return b.String()
}

// Realtime maintains a sliding window over recent packets for live analysis.
type Realtime struct {
	engine       Engine
	window       []Packet
	head         int // logical start index into window (avoids O(n) re-slicing per packet)
	corporate    bool
	windowSecs   float64
	minInterval  float64 // seconds between analyses
	lastAnalyzed float64
	now          func() float64
}

// NewRealtime builds a realtime windowed engine. corporateMode drops
// consumer detectors from window analyses, mirroring batch Correlate.
func NewRealtime(windowSecs uint64, corporateMode bool) *Realtime {
	r := &Realtime{
		engine:      *NewEngine(),
		corporate:   corporateMode,
		windowSecs:  float64(windowSecs),
		minInterval: 5,
	}
	r.lastAnalyzed = nowUnix()
	r.now = defaultNow
	return r
}

// SetClock overrides the time source (tests) and resets the analysis timer.
func (r *Realtime) SetClock(f func() float64) {
	r.now = f
	r.lastAnalyzed = f()
}

func defaultNow() float64 { return nowUnix() }

// Ingest records a packet into the sliding window.
func (r *Realtime) Ingest(pkt Packet) {
	r.window = append(r.window, pkt)
	r.engine.Ingest(pkt)

	cutoff := r.now() - r.windowSecs
	for r.head < len(r.window) && r.window[r.head].Epoch < cutoff {
		r.head++
	}
	// Compact occasionally instead of copying on every ingest.
	if r.head > 512 && r.head*2 >= len(r.window) {
		r.window = append([]Packet(nil), r.window[r.head:]...)
		r.head = 0
	}
}

// WindowPackets returns the live portion of the sliding window.
func (r *Realtime) WindowPackets() []Packet { return r.window[r.head:] }

// ShouldAnalyze reports whether enough time passed since the last run.
func (r *Realtime) ShouldAnalyze() bool {
	return r.now()-r.lastAnalyzed >= r.minInterval
}

// AnalyzeWindow correlates only the current window's packets.
func (r *Realtime) AnalyzeWindow() []Finding {
	r.lastAnalyzed = r.now()
	w := NewEngine()
	w.IngestBatch(r.WindowPackets())
	return w.Correlate(nil, r.corporate)
}
