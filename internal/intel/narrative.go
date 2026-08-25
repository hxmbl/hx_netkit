package intel

import (
	"fmt"
	"sort"
	"strings"
)

// BehavioralSummary is a plain-English narrative of what one device does.
type BehavioralSummary struct {
	IP          string   `json:"ip"`
	Hostname    string   `json:"hostname,omitempty"`
	DeviceType  string   `json:"device_type"`
	Role        string   `json:"role"`
	Activity    string   `json:"activity"`
	Temporal    string   `json:"temporal,omitempty"`
	DNSBehavior string   `json:"dns_behavior,omitempty"`
	RiskSignals []string `json:"risk_signals,omitempty"`
	Narrative   string   `json:"narrative"`
}

// String renders the summary block shown to humans and the AI.
func (b BehavioralSummary) String() string {
	var w strings.Builder
	host := b.Hostname
	if host == "" {
		host = "unknown"
	}
	fmt.Fprintf(&w, "### %s (%s)\n", b.IP, host)
	fmt.Fprintf(&w, "Device: %s\n", b.DeviceType)
	fmt.Fprintf(&w, "Role: %s\n", b.Role)
	fmt.Fprintf(&w, "Activity: %s\n", b.Activity)
	if b.Temporal != "" {
		fmt.Fprintf(&w, "Timing: %s\n", b.Temporal)
	}
	if b.DNSBehavior != "" {
		fmt.Fprintf(&w, "DNS: %s\n", b.DNSBehavior)
	}
	if len(b.RiskSignals) > 0 {
		fmt.Fprintf(&w, "Risk: %s\n", strings.Join(b.RiskSignals, "; "))
	}
	fmt.Fprintf(&w, "Summary: %s\n", b.Narrative)
	return w.String()
}

// GenerateNarratives builds behavioral summaries for every significant IP.
func GenerateNarratives(profiles map[string]*Profile, devices []DeviceInfo, findings []Finding) []BehavioralSummary {
	var out []BehavioralSummary
	for _, p := range profiles {
		if p.PacketCount < MinPacketsForDetection {
			continue
		}
		var ipFindings []Finding
		for i := range findings {
			if findings[i].IP == p.IP {
				ipFindings = append(ipFindings, findings[i])
			}
		}

		var dev *DeviceInfo
		for i := range devices {
			if devices[i].IP == p.IP {
				dev = &devices[i]
				break
			}
		}
		hostname, vendor, osGuess := "", "", ""
		if dev != nil {
			hostname, vendor, osGuess = dev.Hostname, dev.Vendor, dev.OSGuess
		}

		s := BehavioralSummary{
			IP:          p.IP,
			Hostname:    hostname,
			DeviceType:  classifyDeviceType(p, ipFindings, hostname, vendor, osGuess),
			Role:        determineRole(p, ipFindings),
			Activity:    describeActivity(p),
			Temporal:    describeTemporal(p),
			DNSBehavior: describeDNS(p),
			RiskSignals: extractRiskSignals(p, ipFindings),
		}
		s.Narrative = buildNarrative(p, ipFindings, s.DeviceType, s.Role, s.Temporal)
		out = append(out, s)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].RiskSignals) != len(out[j].RiskSignals) {
			return len(out[i].RiskSignals) > len(out[j].RiskSignals)
		}
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return false
	})
	return out
}

func hasKind(findings []Finding, k Kind) bool {
	for i := range findings {
		if findings[i].Kind == k {
			return true
		}
	}
	return false
}

func classifyDeviceType(p *Profile, findings []Finding, hostname, _vendor, osGuess string) string {
	switch {
	case hasKind(findings, KPrinterIoT):
		name := hostname
		if name == "" {
			name = "unknown"
		}
		return fmt.Sprintf("Printer/IoT device (%s)", name)
	case hasKind(findings, KIoTDevice):
		return "IoT/embedded device"
	case hasKind(findings, KServer):
		name := hostname
		if name == "" {
			name = "unknown"
		}
		return fmt.Sprintf("Server (%s)", name)
	case hasKind(findings, KBrowser):
		os := osGuess
		if os == "" {
			os = "unknown OS"
		}
		return fmt.Sprintf("User workstation (%s)", os)
	case hasKind(findings, KGameClient):
		return "Gaming device"
	case hasKind(findings, KVPN):
		return "VPN client"
	}

	switch {
	case p.DNSCount < 3 && p.PacketCount > 30 && p.UDPCount > p.TCPCount:
		return "Embedded/IoT device (low DNS, UDP-dominant)"
	case len(p.SrcIPs) > 5:
		return "Likely server/service (many clients)"
	case p.OutboundCount > p.InboundCount*3:
		return "Outbound-heavy client"
	default:
		return "Generic network device"
	}
}

var roleOrder = []struct {
	kinds []Kind
	role  string
}{
	{[]Kind{KServer}, "serving traffic to other devices"},
	{[]Kind{KBrowser}, "browsing the web"},
	{[]Kind{KStreamingMedia}, "streaming media content"},
	{[]Kind{KCloudSync}, "syncing with cloud services"},
	{[]Kind{KGameClient}, "online gaming"},
	{[]Kind{KVPN}, "tunneling traffic via VPN"},
	{[]Kind{KIoTDevice, KPrinterIoT}, "providing IoT/printer services"},
	{[]Kind{KScanner, KNetworkRecon}, "scanning/reconnaissance"},
	{[]Kind{KBot}, "automated bot activity"},
	{[]Kind{KBeacon, KC2Beacon}, "beaconing to remote host"},
	{[]Kind{KDataExfil}, "high outbound data transfer"},
	{[]Kind{KLateralMovement}, "moving laterally across internal hosts"},
}

func determineRole(p *Profile, findings []Finding) string {
	var roles []string
	for _, r := range roleOrder {
		for _, k := range r.kinds {
			if hasKind(findings, k) {
				roles = append(roles, r.role)
				break
			}
		}
	}
	if len(roles) == 0 {
		inRatio := float64(p.InboundCount) / float64(maxU64(p.PacketCount, 1))
		switch {
		case inRatio > 0.7:
			return "receiving most traffic (possible target/service)"
		case inRatio < 0.3:
			return "sending most traffic (client/uploader)"
		default:
			return "balanced send/receive"
		}
	}
	return strings.Join(roles, ", ")
}

func describeActivity(p *Profile) string {
	var parts []string

	switch {
	case p.PacketCount > 5000:
		parts = append(parts, fmt.Sprintf("very high volume (%d packets)", p.PacketCount))
	case p.PacketCount > 1000:
		parts = append(parts, fmt.Sprintf("moderate volume (%d packets)", p.PacketCount))
	case p.PacketCount > 100:
		parts = append(parts, fmt.Sprintf("light volume (%d packets)", p.PacketCount))
	default:
		parts = append(parts, fmt.Sprintf("minimal traffic (%d packets)", p.PacketCount))
	}

	if pps := p.PPS(); pps > 100.0 {
		parts = append(parts, fmt.Sprintf("high rate (%.0f pkt/s)", pps))
	} else if pps > 10.0 {
		parts = append(parts, fmt.Sprintf("moderate rate (%.1f pkt/s)", pps))
	} else if pps > 1.0 {
		parts = append(parts, fmt.Sprintf("low rate (%.1f pkt/s)", pps))
	}

	if p.OutboundCount > p.InboundCount*3 {
		parts = append(parts, fmt.Sprintf("mostly outbound (%d/%d ↑↓)", p.OutboundCount, p.InboundCount))
	} else if p.InboundCount > p.OutboundCount*3 {
		parts = append(parts, fmt.Sprintf("mostly inbound (%d/%d ↑↓)", p.OutboundCount, p.InboundCount))
	}

	if p.OutboundBytes > 1_000_000 || p.InboundBytes > 1_000_000 {
		parts = append(parts, fmt.Sprintf("heavy payload (%d↑ / %d↓ bytes)", p.OutboundBytes, p.InboundBytes))
	}

	if p.UDPCount > p.TCPCount*2 {
		parts = append(parts, fmt.Sprintf("UDP-dominant (%d UDP vs %d TCP)", p.UDPCount, p.TCPCount))
	} else if p.TCPCount > p.UDPCount*2 {
		parts = append(parts, fmt.Sprintf("TCP-dominant (%d TCP vs %d UDP)", p.TCPCount, p.UDPCount))
	}

	longSessions := countLongSessions(p, 30.0)
	totalSessions := len(p.Sessions)
	if totalSessions > 0 {
		switch {
		case longSessions > 3:
			parts = append(parts, fmt.Sprintf("%d sessions (%d long-lived >30s)", totalSessions, longSessions))
		case totalSessions > 10:
			parts = append(parts, fmt.Sprintf("%d distinct sessions", totalSessions))
		}
	}

	privileged := 0
	for port := range p.SrcPorts {
		if port < 1024 {
			privileged++
		}
	}
	if privileged > 0 {
		parts = append(parts, fmt.Sprintf("listening on %d privileged ports", privileged))
	}
	if p.DestPortEntropy > 3.0 {
		parts = append(parts, fmt.Sprintf("very diverse destination ports (entropy: %.1f)", p.DestPortEntropy))
	}

	if len(p.DestIPs) > 0 {
		avg := float64(p.OutboundCount) / float64(len(p.DestIPs))
		switch {
		case avg > 50.0:
			parts = append(parts, fmt.Sprintf("deep connections to %d hosts (%.0f pkts/dest)", len(p.DestIPs), avg))
		case avg < 3.0 && len(p.DestIPs) > 10:
			parts = append(parts, fmt.Sprintf("shallow connections to %d hosts (%.1f pkts/dest)", len(p.DestIPs), avg))
		}
	}

	if p.PacketCount > 20 {
		stddev := sqrt(p.PacketSizeVariance)
		switch {
		case stddev < 50.0 && p.AvgPacketSize > 100.0:
			parts = append(parts, fmt.Sprintf("uniform packet sizes (~%.0fB ± %.0fB — possible tunnel/VPN)", p.AvgPacketSize, stddev))
		case stddev > 500.0:
			parts = append(parts, fmt.Sprintf("varied packet sizes (%.0fB ± %.0fB — mixed traffic)", p.AvgPacketSize, stddev))
		}
	}

	return strings.Join(parts, ", ")
}

func describeTemporal(p *Profile) string {
	d := p.Duration()
	if d < 1.0 {
		return "brief burst"
	}
	var parts []string
	switch {
	case d > 3600.0:
		parts = append(parts, fmt.Sprintf("active for %.0f minutes", d/60.0))
	case d > 60.0:
		parts = append(parts, fmt.Sprintf("active for %.0f seconds", d))
	default:
		parts = append(parts, fmt.Sprintf("active for %.1f seconds", d))
	}
	switch {
	case p.BurstScore > 1.0:
		parts = append(parts, "highly bursty (clustered traffic)")
	case p.BurstScore > 0.5:
		parts = append(parts, "somewhat bursty")
	case p.BurstScore > 0.0 && p.BurstScore < 0.2:
		parts = append(parts, "very regular spacing")
	}
	if n := len(p.Sessions); n > 50 {
		parts = append(parts, fmt.Sprintf("%d distinct sessions", n))
	} else if n > 10 {
		parts = append(parts, fmt.Sprintf("%d sessions", n))
	}
	return strings.Join(parts, ", ")
}

func describeDNS(p *Profile) string {
	if p.DNSCount == 0 && len(p.DNSDomains) == 0 {
		return "no DNS activity"
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("%d queries, %d unique domains", p.DNSCount, len(p.DNSDomains)))
	if top := p.TopDNS(3); len(top) > 0 {
		strs := make([]string, len(top))
		for i, t := range top {
			strs[i] = fmt.Sprintf("%s(%d)", t.Domain, t.Count)
		}
		parts = append(parts, "top: "+strings.Join(strs, ", "))
	}
	if p.DNSSingleLabels > 5 {
		parts = append(parts, fmt.Sprintf("%d single-label queries (DGA-like)", p.DNSSingleLabels))
	}
	return strings.Join(parts, "; ")
}

func extractRiskSignals(p *Profile, findings []Finding) []string {
	var signals []string
	for i := range findings {
		f := &findings[i]
		pct := f.ConfidencePct()
		switch f.Kind {
		case KC2Beacon:
			signals = append(signals, fmt.Sprintf("C2 beacon detected (%d%% confidence)", pct))
		case KDataExfil:
			signals = append(signals, fmt.Sprintf("data exfiltration pattern (%d%%)", pct))
		case KLateralMovement:
			signals = append(signals, fmt.Sprintf("lateral movement (%d%%)", pct))
		case KScanner:
			signals = append(signals, fmt.Sprintf("scanning activity (%d%%)", pct))
		case KNetworkRecon:
			signals = append(signals, fmt.Sprintf("network reconnaissance (%d%%)", pct))
		case KTor:
			signals = append(signals, fmt.Sprintf("Tor relay/usage (%d%%)", pct))
		case KBot:
			signals = append(signals, fmt.Sprintf("automated bot behavior (%d%%)", pct))
		case KBeacon:
			signals = append(signals, fmt.Sprintf("periodic beaconing (%d%%)", pct))
		case KDNSProfiler:
			signals = append(signals, fmt.Sprintf("DNS profiling/enumeration (%d%%)", pct))
		}
	}
	if p.DNSSingleLabels > 10 {
		signals = append(signals, fmt.Sprintf("DGA-like DNS: %d single-label queries", p.DNSSingleLabels))
	}
	if internal := p.InternalDestCount(); internal > 5 && p.OutboundCount > 20 {
		signals = append(signals, fmt.Sprintf("talking to %d internal hosts (possible lateral movement)", internal))
	}
	return signals
}

func countLongSessions(p *Profile, min float64) int {
	n := 0
	for _, s := range p.Sessions {
		if s.LastPacket-s.FirstPacket > min {
			n++
		}
	}
	return n
}

func buildNarrative(p *Profile, findings []Finding, deviceType, role, temporal string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is %s on the network. ", deviceType, role)

	if len(p.DestIPs) > 0 {
		internal := p.InternalDestCount()
		external := len(p.DestIPs) - internal
		switch {
		case internal > 0 && external > 0:
			fmt.Fprintf(&b, "Talks to %d internal and %d external hosts. ", internal, external)
		case internal > 0:
			fmt.Fprintf(&b, "Talks to %d internal hosts. ", internal)
		default:
			fmt.Fprintf(&b, "Talks to %d external hosts. ", external)
		}
		top := p.topDestIPs(3)
		b.WriteString("Top destinations: " + top + ". ")
	}

	if n := len(p.DNSDomains); n > 30 {
		fmt.Fprintf(&b, "Resolved %d unique domains — extensive web activity. ", n)
	} else if n > 10 {
		fmt.Fprintf(&b, "Resolved %d domains. ", n)
	} else if n > 0 {
		top := p.TopDNS(3)
		names := make([]string, len(top))
		for i, t := range top {
			names[i] = t.Domain
		}
		fmt.Fprintf(&b, "Primarily contacts %s. ", strings.Join(names, ", "))
	}

	if topPorts := p.TopDestPorts(3); len(topPorts) > 0 {
		strs := make([]string, len(topPorts))
		for i, tp := range topPorts {
			strs[i] = fmt.Sprintf("%d(%d)", tp.Port, tp.Count)
		}
		fmt.Fprintf(&b, "Top ports: %s. ", strings.Join(strs, ", "))
	}

	if long := countLongSessions(p, 30.0); long > 3 {
		fmt.Fprintf(&b, "%d long-lived sessions (>30s). ", long)
	}

	privileged := 0
	for port := range p.SrcPorts {
		if port < 1024 {
			privileged++
		}
	}
	if privileged > 0 {
		fmt.Fprintf(&b, "Listening on %d privileged ports. ", privileged)
	}

	if p.PacketCount > 20 {
		stddev := sqrt(p.PacketSizeVariance)
		switch {
		case stddev < 50.0 && p.AvgPacketSize > 100.0:
			fmt.Fprintf(&b, "Uniform packet sizes (~%.0fB) suggest encrypted tunnel. ", p.AvgPacketSize)
		case stddev > 500.0:
			fmt.Fprintf(&b, "Highly varied packet sizes (%.0fB ± %.0fB) — mixed interactive traffic. ", p.AvgPacketSize, stddev)
		}
	}

	if len(p.DestIPs) > 0 {
		avg := float64(p.OutboundCount) / float64(len(p.DestIPs))
		switch {
		case avg > 50.0:
			fmt.Fprintf(&b, "Deep connections (%.0f pkts/dest) — sustained communication. ", avg)
		case avg < 3.0 && len(p.DestIPs) > 10:
			fmt.Fprintf(&b, "Shallow connections (%.1f pkts/dest across %d hosts) — scanning or probing. ", avg, len(p.DestIPs))
		}
	}

	if p.OutboundBytes > 1_000_000 {
		fmt.Fprintf(&b, "Heavy outbound payload (%d MB). ", p.OutboundBytes/1_000_000)
	}
	if p.InboundBytes > 1_000_000 {
		fmt.Fprintf(&b, "Heavy inbound payload (%d MB). ", p.InboundBytes/1_000_000)
	}

	hasC2 := hasKind(findings, KC2Beacon)
	hasExfil := hasKind(findings, KDataExfil)
	hasScan := hasKind(findings, KScanner) || hasKind(findings, KNetworkRecon)
	hasLateral := hasKind(findings, KLateralMovement)

	if hasC2 || hasExfil || hasScan || hasLateral {
		b.WriteString("⚠ Suspicious: ")
		var flags []string
		if hasC2 {
			flags = append(flags, "C2 beaconing")
		}
		if hasExfil {
			flags = append(flags, "data exfiltration")
		}
		if hasScan {
			flags = append(flags, "scanning")
		}
		if hasLateral {
			flags = append(flags, "lateral movement")
		}
		fmt.Fprintf(&b, "%s. ", strings.Join(flags, ", "))
	}

	if temporal != "" {
		fmt.Fprintf(&b, "%s.", temporal)
	}

	return b.String()
}

func (p *Profile) topDestIPs(n int) string {
	type dc struct {
		ip string
		c  uint64
	}
	list := make([]dc, 0, len(p.DestIPs))
	for ip, c := range p.DestIPs {
		list = append(list, dc{ip, c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].c != list[j].c {
			return list[i].c > list[j].c
		}
		return list[i].ip < list[j].ip
	})
	if len(list) > n {
		list = list[:n]
	}
	parts := make([]string, len(list))
	for i, d := range list {
		parts[i] = fmt.Sprintf("%s(%d)", d.ip, d.c)
	}
	return strings.Join(parts, ", ")
}
