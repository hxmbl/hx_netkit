package intel

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Kind classifies a detector finding.
type Kind int

const (
	KBrowser Kind = iota
	KBot
	KServer
	KIoTDevice
	KDNSProfiler
	KBeacon
	KScanner
	KStreamingMedia
	KCloudSync
	KVPN
	KTor
	KGameClient
	KIoTCoordinator
	KLateralMovement
	KDataExfil
	KC2Beacon
	KNetworkRecon
	KPrinterIoT
	KUnknown
)

var kindNames = map[Kind]string{
	KBrowser:         "BROWSER",
	KBot:             "BOT",
	KServer:          "SERVER",
	KIoTDevice:       "IOT",
	KDNSProfiler:     "DNS_PROFILER",
	KBeacon:          "BEACON",
	KScanner:         "SCANNER",
	KStreamingMedia:  "STREAMING",
	KCloudSync:       "CLOUD_SYNC",
	KVPN:             "VPN",
	KTor:             "TOR",
	KGameClient:      "GAME",
	KIoTCoordinator:  "IOT_COORD",
	KLateralMovement: "LATERAL_MOVEMENT",
	KDataExfil:       "DATA_EXFIL",
	KC2Beacon:        "C2_BEACON",
	KNetworkRecon:    "NET_RECON",
	KPrinterIoT:      "PRINTER_IOT",
	KUnknown:         "UNKNOWN",
}

func (k Kind) String() string { return kindNames[k] }

// Finding is one detector verdict for an IP.
type Finding struct {
	IP         string   `json:"ip"`
	Kind       Kind     `json:"-"`
	Confidence float64  `json:"confidence"`
	Detail     string   `json:"detail"`
	Indicators []string `json:"indicators,omitempty"`
}

func (f Finding) KindName() string { return f.Kind.String() }

// ConfidencePct returns the confidence as an integer percent.
func (f Finding) ConfidencePct() int { return int(f.Confidence * 100) }

// String renders a human-readable one-liner.
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s (%d%%) — %s", f.Kind, f.IP, f.ConfidencePct(), f.Detail)
}

// MarshalJSON emits the detector kind by name so serialized findings stay
// self-describing (the AI report and any JSON consumers depend on it).
func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		IP            string   `json:"ip"`
		Type          string   `json:"type"`
		Kind          string   `json:"kind"`
		Confidence    float64  `json:"confidence"`
		ConfidencePct int      `json:"confidence_pct"`
		Detail        string   `json:"detail"`
		Indicators    []string `json:"indicators,omitempty"`
	}{
		IP:            f.IP,
		Type:          f.Kind.String(),
		Kind:          f.Kind.String(),
		Confidence:    f.Confidence,
		ConfidencePct: f.ConfidencePct(),
		Detail:        f.Detail,
		Indicators:    f.Indicators,
	})
}

// DeviceInfo is what nmap knows about a host; used by device-aware detectors.
type DeviceInfo struct {
	IP       string
	MAC      string
	Hostname string
	Vendor   string
	OSGuess  string
	Ports    string
}

// ── Domain intelligence tables ──────────────────────────────────────────────

var browserDomains = []string{
	"google.com", "googleapis.com", "gstatic.com", "cloudflare.com",
	"mozilla.org", "apple.com", "microsoft.com", "windows.com", "windowsupdate.com",
	"akamai.net", "akamaized.net", "fastly.net", "facebook.com", "fbcdn.net",
	"twitter.com", "x.com", "youtube.com", "ytimg.com", "amazonaws.com",
	"azureedge.net", "edgecastcdn.net", "cloudfront.net", "bing.com",
	"reddit.com", "redditstatic.com", "discord.com", "discordapp.com",
}

var cloudDomains = []string{
	"icloud.com", "apple.com", "googleapis.com", "drive.google.com",
	"dropbox.com", "onedrive.live.com", "box.com", "sync", "backup",
	"amazonaws.com", "azure.com", "backblaze.com",
}

var streamingDomains = []string{
	"video", "media", "hls", "dash", "stream", "netflix.com",
	"hulu.com", "primevideo.com", "disneyplus.com", "hbomax.com",
	"twitch.tv", "ttvnw.net", "youtube.com", "youtu.be", "vimeo.com",
	"soundcloud.com", "spotify.com",
}

var iotPorts = []uint32{5353, 1900, 5355, 5683, 5684, 8883, 1883, 5672, 15672, 8083}

var gamePorts = []uint32{
	27015, 27016, 27017, 27018, 27019, 27020, // Steam
	3478, 3479, 3480, // PlayStation
	3074,                   // Xbox
	6112, 6113, 6114, 6115, // Battle.net
	1119, 1120, 3724, // Blizzard
	25565, 25566, 19132, 19133, // Minecraft
	7777, // Unreal Engine
}

var torPorts = []uint32{9001, 9002, 9003, 9030, 9031, 9150, 443}

var vpnPorts = []uint32{1194, 4500, 500, 1723, 1195, 8443, 443}

var reconMgmtPorts = []uint32{22, 23, 80, 443, 8080, 3389, 5900, 21, 2323, 9100}

var printerIotSignalPorts = []uint32{5353, 1900, 5355, 5683, 5684, 9100, 631}

// ── helpers ─────────────────────────────────────────────────────────────────

func emit(ip string, k Kind, conf float64, indicators []string) *Finding {
	return &Finding{
		IP:         ip,
		Kind:       k,
		Confidence: conf,
		Detail:     strings.Join(indicators, "; "),
		Indicators: indicators,
	}
}

func intervalsBetween(times []float64, noiseFloor float64) []float64 {
	var out []float64
	for i := 1; i < len(times); i++ {
		d := times[i] - times[i-1]
		if d < 0 {
			d = -d
		}
		if d > noiseFloor {
			out = append(out, d)
		}
	}
	return out
}

func meanVar(xs []float64) (mean, variance float64, ok bool) {
	if len(xs) == 0 {
		return 0, 0, false
	}
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		d := x - mean
		variance += d * d
	}
	variance /= float64(len(xs))
	return mean, variance, true
}

func containsU32(list []uint32, v uint32) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func domainHasSuffix(domains map[string]uint64, suffixes []string) []string {
	var hits []string
	for d := range domains {
		for _, s := range suffixes {
			if strings.HasSuffix(d, s) {
				hits = append(hits, d)
				break
			}
		}
	}
	sort.Strings(hits)
	return hits
}

func domainContains(domains map[string]uint64, subs []string) []string {
	var hits []string
	for d := range domains {
		for _, s := range subs {
			if strings.Contains(d, s) {
				hits = append(hits, d)
				break
			}
		}
	}
	sort.Strings(hits)
	return hits
}

// ── benign detectors ────────────────────────────────────────────────────────

func detectBrowser(p *Profile) *Finding {
	score := 0.0
	var ind []string

	if c := p.DestPorts[443]; c > BrowserHTTPSMin {
		score += 0.25
		ind = append(ind, fmt.Sprintf("%d HTTPS connections", c))
	}
	if len(p.DNSDomains) > BrowserDomainsMin {
		score += 0.25
		ind = append(ind, fmt.Sprintf("%d unique domains resolved", len(p.DNSDomains)))
	}
	if len(p.SrcPorts) > BrowserSrcPortsMin {
		score += 0.15
		ind = append(ind, fmt.Sprintf("%d ephemeral source ports", len(p.SrcPorts)))
	}
	if hits := domainHasSuffix(p.DNSDomains, browserDomains); len(hits) >= BrowserCDNHitsMin {
		score += 0.2
		ind = append(ind, fmt.Sprintf("%d browser CDNs contacted", len(hits)))
	}
	if p.DestPortEntropy > BrowserPortEntropyMin {
		score += 0.1
		ind = append(ind, fmt.Sprintf("high port entropy: %.2f", p.DestPortEntropy))
	}
	if len(p.DestIPs) > BrowserDestIPsMin {
		score += 0.1
		ind = append(ind, fmt.Sprintf("%d distinct destination IPs", len(p.DestIPs)))
	}
	if score >= FindingThreshold {
		return emit(p.IP, KBrowser, minF(score, 1), ind)
	}
	return nil
}

func detectBot(p *Profile) *Finding {
	score := 0.0
	var ind []string

	if p.PacketCount < BotMinPackets {
		return nil
	}

	intervals := intervalsBetween(p.interArrivalTimes, BotIntervalNoiseFloor)
	if len(intervals) >= BotMinSamples {
		mean, variance, ok := meanVar(intervals)
		if ok && mean > 0 {
			cv := sqrt(variance) / mean
			if cv < BotPrecisionCV && mean > BotPrecisionMean {
				score += 0.4
				ind = append(ind, fmt.Sprintf("precision beacon: %.2fs interval (CV: %.4f)", mean, cv))
			} else if cv < BotRegularCV && mean > BotRegularMean {
				score += 0.3
				ind = append(ind, fmt.Sprintf("regular interval: %.1fs (CV: %.3f)", mean, cv))
			}

			autocorr := 0.0
			n := len(intervals)
			maxLag := n
			if maxLag > 20 {
				maxLag = 20
			}
			for lag := 1; lag < maxLag; lag++ {
				var sum float64
				count := 0
				for i := 0; i+lag < n; i++ {
					sum += (intervals[i] - mean) * (intervals[i+lag] - mean)
					count++
				}
				if count > 0 {
					corr := sum / (float64(count) * maxF(variance, 0.001))
					if corr > autocorr {
						autocorr = corr
					}
				}
			}
			if autocorr > BotAutocorrMin {
				score += 0.2
				ind = append(ind, fmt.Sprintf("high autocorrelation: %.3f", autocorr))
			}
		}
	}

	if port, count := maxEntryU32(p.DestPorts); port > 0 || count > 0 {
		pct := float64(count) / float64(p.PacketCount)
		if pct > BotMonotonicPortPct && count > BotMonotonicPortMin {
			score += 0.25
			ind = append(ind, fmt.Sprintf("%.0f%% of traffic to port %d", pct*100, port))
		}
	}

	if len(p.DNSDomains) <= BotLowDNSDomains && p.OutboundCount > BotLowDNSOutbound {
		score += 0.2
		ind = append(ind, "pre-programmed IPs, minimal DNS")
	}

	if p.BurstScore > BotBurstMin && p.BurstScore < BotBurstMax && p.PacketCount > 50 {
		score += 0.1
		ind = append(ind, fmt.Sprintf("regular burst pattern (CV: %.3f)", p.BurstScore))
	}

	if score >= BotThreshold {
		return emit(p.IP, KBot, minF(score, 1), ind)
	}
	return nil
}

func detectServer(p *Profile) *Finding {
	score := 0.0
	var ind []string

	if len(p.SrcIPs) > ServerClientsMin {
		score += 0.3
		ind = append(ind, fmt.Sprintf("%d unique clients", len(p.SrcIPs)))
	}

	var listening []uint32
	for port := range p.SrcPorts {
		if port < 1024 {
			listening = append(listening, port)
		}
	}
	sort.Slice(listening, func(i, j int) bool { return listening[i] < listening[j] })
	if len(listening) > 0 {
		score += 0.25
		strs := make([]string, len(listening))
		for i, pt := range listening {
			strs[i] = fmt.Sprint(pt)
		}
		ind = append(ind, "listening on: "+strings.Join(strs, ", "))
	}

	if p.InboundCount > 0 {
		ratio := float64(p.InboundCount) / float64(maxU64(p.OutboundCount, 1))
		if ratio > ServerInboundRatio {
			score += 0.2
			ind = append(ind, fmt.Sprintf("inbound ratio: %.1f:1", ratio))
		}
	}

	if len(p.DestPorts) > ServerDestPortsMin {
		score += 0.15
		ind = append(ind, fmt.Sprintf("responding to %d client ports", len(p.DestPorts)))
	}

	longSessions := 0
	for _, s := range p.Sessions {
		if s.LastPacket-s.FirstPacket > ServerLongSessionSecs {
			longSessions++
		}
	}
	if longSessions > ServerLongSessionsMin {
		score += 0.1
		ind = append(ind, fmt.Sprintf("%d long-lived sessions", longSessions))
	}

	if score >= FindingThreshold {
		return emit(p.IP, KServer, minF(score, 1), ind)
	}
	return nil
}

func detectIoT(p *Profile) *Finding {
	score := 0.0
	var ind []string

	var mcastHits []string
	for port := range p.DestPorts {
		if containsU32(iotPorts, port) {
			mcastHits = append(mcastHits, fmt.Sprint(port))
		}
	}
	sort.Strings(mcastHits)
	if len(mcastHits) > 0 {
		score += 0.3
		ind = append(ind, "multicast: "+strings.Join(mcastHits, ", "))
	}

	if len(p.DestIPs) <= IoTMaxDestIPs && p.PacketCount > 30 {
		score += 0.15
		ind = append(ind, fmt.Sprintf("only %d external IPs", len(p.DestIPs)))
	}

	if d := p.Duration(); d > 0 {
		if pps := float64(p.PacketCount) / d; pps < IoTMaxPPS && p.PacketCount > 20 {
			score += 0.15
			ind = append(ind, fmt.Sprintf("low rate: %.1f pps", pps))
		}
	}

	if p.DNSCount < IoTMaxDNS && p.PacketCount > 30 {
		score += 0.15
		ind = append(ind, fmt.Sprintf("%d DNS queries", p.DNSCount))
	}

	if p.BurstScore > IoTHeartbeatBurstMin && p.BurstScore < IoTHeartbeatBurstMax && p.Duration() > 10.0 {
		score += 0.1
		ind = append(ind, "heartbeat pattern")
	}

	if p.UDPCount > p.TCPCount && p.UDPCount > 15 {
		score += 0.1
		ind = append(ind, "UDP-dominant")
	}

	if score >= FindingThreshold {
		return emit(p.IP, KIoTDevice, minF(score, 1), ind)
	}
	return nil
}

func detectDNSProfiler(p *Profile) *Finding {
	score := 0.0
	var ind []string

	if d := p.Duration(); d > 0 {
		if qps := float64(p.DNSCount) / d; qps > DNSQpsHigh {
			score += 0.35
			ind = append(ind, fmt.Sprintf("high DNS rate: %.1f qps", qps))
		}
	}
	if len(p.DNSDomains) > DNSDomainsHigh {
		score += 0.3
		ind = append(ind, fmt.Sprintf("%d unique domains", len(p.DNSDomains)))
	}
	if p.DNSCount > 25 && p.OutboundCount < p.DNSCount/4 {
		score += 0.2
		ind = append(ind, "probing domains without connecting")
	}
	if p.DNSSingleLabels > DNSSingleLabelsHigh {
		score += 0.15
		ind = append(ind, fmt.Sprintf("%d single-label queries", p.DNSSingleLabels))
	}
	if score >= FindingThreshold {
		return emit(p.IP, KDNSProfiler, minF(score, 1), ind)
	}
	return nil
}

func detectBeacon(p *Profile) *Finding {
	score := 0.0
	var ind []string

	intervals := intervalsBetween(p.interArrivalTimes, BeaconIntervalNoiseFloor)
	if len(intervals) < BeaconMinSamples {
		return nil
	}
	mean, variance, ok := meanVar(intervals)
	if !ok || mean < BeaconMinMean {
		return nil
	}
	cv := sqrt(variance) / mean

	if cv < BeaconTightCV && mean > BeaconTightMean {
		score += 0.5
		ind = append(ind, fmt.Sprintf("tight beacon: %.1fs ± %.3fs (CV: %.4f)", mean, sqrt(variance), cv))
	}
	if cv > BeaconJitterCVMin && cv < BeaconJitterCVMax && mean > BeaconJitterMean {
		score += 0.35
		ind = append(ind, fmt.Sprintf("jittered beacon: %.1fs (CV: %.3f)", mean, cv))
	}
	if len(p.DestIPs) == 1 && p.DNSCount < 3 {
		score += 0.2
		ind = append(ind, "single C2 destination")
	}
	if p.PacketCount > 30 && p.AvgPacketSize < 200.0 {
		score += 0.1
		ind = append(ind, "low-payload keep-alive")
	}
	if score >= FindingThreshold {
		return emit(p.IP, KBeacon, minF(score, 1), ind)
	}
	return nil
}

func detectScanner(p *Profile) *Finding {
	score := 0.0
	var ind []string

	if len(p.DestPorts) > ScannerPortThreshold {
		score += 0.35
		ind = append(ind, fmt.Sprintf("port scanning: %d unique ports", len(p.DestPorts)))
	}

	avgPktsPerDest := 0.0
	if len(p.DestIPs) > 0 {
		avgPktsPerDest = float64(p.OutboundCount) / float64(len(p.DestIPs))
	}
	if len(p.DestIPs) > ScannerHostThreshold && avgPktsPerDest < ScannerPktsPerHost {
		score += 0.3
		ind = append(ind, fmt.Sprintf("network scan: %d hosts, %.1f pkts/host", len(p.DestIPs), avgPktsPerDest))
	}

	if p.OutboundCount > ScannerOutboundMin &&
		p.InboundCount < p.OutboundCount/uint64(ScannerResponseRatio) {
		score += 0.2
		ind = append(ind, "SYN scan pattern (high outbound, low response)")
	}

	ports := make([]uint32, 0, len(p.DestPorts))
	for pt := range p.DestPorts {
		ports = append(ports, pt)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	if len(ports) >= 5 {
		seq := 0
		for i := 1; i < len(ports); i++ {
			if ports[i]-ports[i-1] <= 2 {
				seq++
			}
		}
		if float64(seq)/float64(len(ports)) > ScannerSequentialRatio {
			score += 0.15
			ind = append(ind, "sequential port scan")
		}
	}
	if score >= FindingThreshold {
		return emit(p.IP, KScanner, minF(score, 1), ind)
	}
	return nil
}

func detectStreaming(p *Profile) *Finding {
	score := 0.0
	var ind []string

	duration := p.Duration()
	if duration < StreamMinDuration {
		return nil
	}
	if p.PacketCount > StreamSustainedPkts && duration > StreamSustainedDuration {
		score += 0.2
		ind = append(ind, fmt.Sprintf("sustained: %.0fs, %d pkts", duration, p.PacketCount))
	}
	if hits := domainContains(p.DNSDomains, streamingDomains); len(hits) > 0 {
		top := hits
		if len(top) > 3 {
			top = top[:3]
		}
		score += 0.3
		ind = append(ind, "streaming services: "+strings.Join(top, ", "))
	}
	if p.UDPCount > p.TCPCount*StreamUDPDominance && p.UDPCount > StreamMinUDP {
		score += 0.2
		ind = append(ind, fmt.Sprintf("UDP-dominant: %d UDP, %d TCP", p.UDPCount, p.TCPCount))
	}
	if duration > 0 {
		if pps := float64(p.PacketCount) / duration; pps > StreamHighPPS {
			score += 0.15
			ind = append(ind, fmt.Sprintf("high rate: %.0f pps", pps))
		}
	}
	if score >= FindingThreshold {
		return emit(p.IP, KStreamingMedia, minF(score, 1), ind)
	}
	return nil
}

func detectCloudSync(p *Profile) *Finding {
	score := 0.0
	var ind []string

	if hits := domainContains(p.DNSDomains, cloudDomains); len(hits) > 0 {
		top := hits
		if len(top) > 3 {
			top = top[:3]
		}
		score += 0.3
		ind = append(ind, "cloud: "+strings.Join(top, ", "))
	}
	if len(p.DNSDomains) <= 5 && p.DNSCount > 15 {
		if dom, cnt := maxEntryStr(p.DNSDomains); dom != "" && cnt > 8 {
			score += 0.2
			ind = append(ind, fmt.Sprintf("repeated %s: %dx", dom, cnt))
		}
	}
	if p.InboundCount > 15 && p.OutboundCount > 15 {
		ratio := minF(float64(p.InboundCount)/float64(p.OutboundCount),
			float64(p.OutboundCount)/float64(p.InboundCount))
		if ratio > 0.3 {
			score += 0.15
			ind = append(ind, "steady bidirectional sync")
		}
	}
	if score >= FindingThreshold {
		return emit(p.IP, KCloudSync, minF(score, 1), ind)
	}
	return nil
}

func detectVPN(p *Profile) *Finding {
	score := 0.0
	var ind []string

	var vpnHits []string
	for port, count := range p.DestPorts {
		if containsU32(vpnPorts, port) {
			vpnHits = append(vpnHits, fmt.Sprintf("%d(%d)", port, count))
		}
	}
	sort.Strings(vpnHits)
	if len(vpnHits) > 0 {
		score += 0.3
		ind = append(ind, "VPN ports: "+strings.Join(vpnHits, ", "))
	}
	if len(p.DestIPs) <= VPNMaxDestIPs && p.PacketCount > VPNMinPackets {
		score += 0.2
		ind = append(ind, fmt.Sprintf("tunnel to %d IPs", len(p.DestIPs)))
	}
	if ip, count := maxEntryStr(p.DestIPs); ip != "" {
		if float64(count)/float64(p.PacketCount) > VPNTunnelRatio && count > VPNTunnelMin {
			score += 0.2
			ind = append(ind, "dedicated tunnel to "+ip)
		}
	}
	if p.PacketCount > 50 && p.PacketSizeVariance < VPNUniformVarianceMax {
		score += 0.1
		ind = append(ind, "uniform packet sizes (encrypted tunnel)")
	}
	if score >= FindingThreshold {
		return emit(p.IP, KVPN, minF(score, 1), ind)
	}
	return nil
}

func detectTor(p *Profile) *Finding {
	score := 0.0
	var ind []string

	var torHits []string
	for port := range p.SrcPorts {
		if containsU32(torPorts, port) {
			torHits = append(torHits, fmt.Sprint(port))
		}
	}
	sort.Strings(torHits)
	if len(torHits) > 0 {
		score += 0.35
		ind = append(ind, "Tor ports: "+strings.Join(torHits, ", "))
	}
	if len(p.SrcIPs) > TorRelayClientsMin && p.PacketCount > TorRelayPacketsMin {
		score += 0.2
		ind = append(ind, fmt.Sprintf("relay behavior: %d clients, %d pkts", len(p.SrcIPs), p.PacketCount))
	}
	long := 0
	for _, s := range p.Sessions {
		if s.LastPacket-s.FirstPacket > TorCircuitDuration {
			long++
		}
	}
	if long > TorCircuitsMin {
		score += 0.15
		ind = append(ind, fmt.Sprintf("%d long-lived circuits", long))
	}
	if score >= FindingThreshold {
		return emit(p.IP, KTor, minF(score, 1), ind)
	}
	return nil
}

func detectGame(p *Profile) *Finding {
	score := 0.0
	var ind []string

	var gameHits []string
	for port := range p.DestPorts {
		if containsU32(gamePorts, port) {
			gameHits = append(gameHits, fmt.Sprint(port))
		}
	}
	sort.Strings(gameHits)
	if len(gameHits) > 0 {
		score += 0.35
		ind = append(ind, "game ports: "+strings.Join(gameHits, ", "))
	}
	if p.BurstScore > GameBurstMin && p.PacketCount > 50 {
		score += 0.2
		ind = append(ind, fmt.Sprintf("bursty pattern (CV: %.2f)", p.BurstScore))
	}
	if d := p.Duration(); d > 0 {
		pps := float64(p.PacketCount) / d
		if pps > GamePPSMin && pps < GamePPSMax {
			score += 0.15
			ind = append(ind, fmt.Sprintf("game-like rate: %.0f pps", pps))
		}
	}
	if p.UDPCount > p.TCPCount {
		score += 0.1
		ind = append(ind, "UDP-dominant")
	}
	if score >= FindingThreshold {
		return emit(p.IP, KGameClient, minF(score, 1), ind)
	}
	return nil
}

// ── threat detectors ────────────────────────────────────────────────────────

func detectLateralMovement(p *Profile, all map[string]*Profile) *Finding {
	score := 0.0
	var ind []string

	var internalDests []string
	for ip := range p.DestIPs {
		if IsPrivateIP(ip) {
			internalDests = append(internalDests, ip)
		}
	}
	internalCount := len(internalDests)
	if internalCount < LateralMinInternalHosts {
		return nil
	}

	score += 0.25
	ind = append(ind, fmt.Sprintf("connecting to %d internal hosts", internalCount))

	var mgmtUsed []uint32
	for port := range p.DestPorts {
		if port < PrivilegedPortMax || port == 8080 || port == 3389 {
			mgmtUsed = append(mgmtUsed, port)
		}
	}
	sort.Slice(mgmtUsed, func(i, j int) bool { return mgmtUsed[i] < mgmtUsed[j] })
	if len(mgmtUsed) >= LateralMinMgmtPorts {
		score += 0.25
		strs := make([]string, len(mgmtUsed))
		for i, pt := range mgmtUsed {
			strs[i] = fmt.Sprint(pt)
		}
		ind = append(ind, fmt.Sprintf("using %d management ports: %s", len(mgmtUsed), strings.Join(strs, ", ")))
	}

	var internalPkts uint64
	for ip, c := range p.DestIPs {
		if IsPrivateIP(ip) {
			internalPkts += c
		}
	}
	totalOut := maxU64(p.OutboundCount, 1)
	internalRatio := float64(internalPkts) / float64(totalOut)
	if internalRatio > LateralInternalRatio {
		score += 0.2
		ind = append(ind, fmt.Sprintf("%.0f%% traffic to internal hosts", internalRatio*100))
	}

	othersCanSee := 0
	for _, dest := range internalDests {
		if _, ok := all[dest]; ok {
			othersCanSee++
		}
	}
	if othersCanSee >= LateralOverlapMin {
		score += 0.15
		ind = append(ind, fmt.Sprintf("%d target hosts have traffic profiles", othersCanSee))
	}

	if d := p.Duration(); d > 0 && float64(internalCount)/d > LateralScanRate {
		score += 0.1
		ind = append(ind, fmt.Sprintf("rapid internal scanning: %.1f hosts/s", float64(internalCount)/d))
	}

	if score >= FindingThreshold {
		return emit(p.IP, KLateralMovement, minF(score, 1), ind)
	}
	return nil
}

func detectDataExfil(p *Profile) *Finding {
	score := 0.0
	var ind []string

	type destCount struct {
		ip string
		c  uint64
	}
	var external []destCount
	for ip, c := range p.DestIPs {
		if !IsPrivateIP(ip) {
			external = append(external, destCount{ip, c})
		}
	}
	if len(external) == 0 {
		return nil
	}
	sort.Slice(external, func(i, j int) bool { return external[i].c > external[j].c })

	if p.InboundCount > 0 {
		ratio := float64(p.OutboundCount) / float64(p.InboundCount)
		if ratio > ExfilOutboundRatio && p.OutboundCount > ExfilMinOutbound {
			score += 0.35
			ind = append(ind, fmt.Sprintf("high outbound ratio: %.1f:1 (%d out, %d in)",
				ratio, p.OutboundCount, p.InboundCount))
		}
	}
	if top := external[0]; float64(top.c)/float64(p.PacketCount) > ExfilSingleDestPct && top.c > ExfilSingleDestMin {
		score += 0.3
		ind = append(ind, fmt.Sprintf("%d%% of outbound to single IP %s (%d)",
			int(float64(top.c)/float64(p.PacketCount)*100), top.ip, top.c))
	}
	if len(p.DNSDomains) <= ExfilLowDNSDomains && p.OutboundCount > ExfilLowDNSOutbound {
		score += 0.15
		ind = append(ind, fmt.Sprintf("only %d DNS domains with %d outbound packets (pre-configured destination)",
			len(p.DNSDomains), p.OutboundCount))
	}
	if d := p.Duration(); d > ExfilSustainedDuration && p.OutboundCount > ExfilSustainedOutbound {
		score += 0.1
		ind = append(ind, fmt.Sprintf("sustained over %.0fs", d))
	}
	if score >= FindingThreshold {
		return emit(p.IP, KDataExfil, minF(score, 1), ind)
	}
	return nil
}

func detectC2Beacon(p *Profile) *Finding {
	score := 0.0
	var ind []string

	intervals := intervalsBetween(p.interArrivalTimes, C2IntervalNoiseFloor)
	if len(intervals) < C2MinSamples {
		return nil
	}
	mean, variance, _ := meanVar(intervals)
	cv := sqrt(variance) / mean

	isRegular := cv < C2RegularCV && mean > C2RegularMean
	isJittered := cv >= C2JitterCVMin && cv < C2JitterCVMax && mean > C2JitterMean
	if !isRegular && !isJittered {
		return nil
	}

	if isRegular {
		score += 0.3
		ind = append(ind, fmt.Sprintf("regular beacon: %.1fs ± %.3fs (CV: %.4f)", mean, sqrt(variance), cv))
	} else {
		score += 0.2
		ind = append(ind, fmt.Sprintf("jittered beacon: %.1fs (CV: %.3f)", mean, cv))
	}

	extCount := p.ExternalDestCount()
	var singleExt string
	for ip := range p.DestIPs {
		if !IsPrivateIP(ip) {
			singleExt = ip
		}
	}
	if extCount == 1 && singleExt != "" {
		score += 0.2
		ind = append(ind, "single external destination: "+singleExt)
	}

	if p.DNSCount < 5 && p.OutboundCount > 20 {
		score += 0.15
		ind = append(ind, fmt.Sprintf("%d DNS queries, %d outbound (minimal DNS)", p.DNSCount, p.OutboundCount))
	}

	avgOut := 0.0
	if len(p.DestIPs) > 0 {
		avgOut = float64(p.OutboundCount) / float64(len(p.DestIPs))
	}
	if avgOut < C2SmallPayloadMax && avgOut > 0 {
		score += 0.1
		ind = append(ind, fmt.Sprintf("small payloads: %.1f pkts/dest", avgOut))
	}
	if p.PacketCount < 500 && len(p.DNSDomains) <= 2 {
		score += 0.1
		ind = append(ind, "reconnaissance-style low volume")
	}
	if score >= FindingThreshold {
		return emit(p.IP, KC2Beacon, minF(score, 1), ind)
	}
	return nil
}

func detectNetworkRecon(p *Profile) *Finding {
	score := 0.0
	var ind []string

	var mgmtHits []string
	for port := range p.DestPorts {
		if containsU32(reconMgmtPorts, port) {
			mgmtHits = append(mgmtHits, fmt.Sprint(port))
		}
	}
	sort.Strings(mgmtHits)
	if len(mgmtHits) < ReconMinMgmtPorts {
		return nil
	}
	score += 0.3
	ind = append(ind, "probing management ports: "+strings.Join(mgmtHits, ", "))

	var internalDests []string
	for ip := range p.DestIPs {
		if IsPrivateIP(ip) {
			internalDests = append(internalDests, ip)
		}
	}
	if len(internalDests) >= ReconMinInternalHosts {
		score += 0.25
		ind = append(ind, fmt.Sprintf("targeting %d internal hosts", len(internalDests)))
	}

	avgPktsPerDest := 0.0
	if len(internalDests) > 0 {
		avgPktsPerDest = float64(p.OutboundCount) / float64(len(internalDests))
	}
	if avgPktsPerDest < ReconMaxPktsPerHost && avgPktsPerDest > 0 {
		score += 0.2
		ind = append(ind, fmt.Sprintf("light touch: %.1f pkts/host (probe pattern)", avgPktsPerDest))
	}
	if p.InboundCount < p.OutboundCount/4 && p.OutboundCount > 20 {
		score += 0.15
		ind = append(ind, "mostly unanswered probes")
	}
	if p.DNSCount == 0 && len(internalDests) > 3 {
		score += 0.1
		ind = append(ind, "no DNS (targeting known IPs)")
	}
	if score >= FindingThreshold {
		return emit(p.IP, KNetworkRecon, minF(score, 1), ind)
	}
	return nil
}

var printerKeywords = []string{"printer", "print", "brother", "canon", "epson", "hp", "xerox", "ricoh"}
var iotKeywords = []string{"smart tv", "roku", "chromecast", "alexa", "echo", "home", "hub", "nest", "ring"}

// hasToken reports whether kw appears in hay as a standalone alphanumeric
// token (so "hp" matches "HP LaserJet" but not "php" or "shop").
func hasToken(hay, kw string) bool {
	start := -1
	isAlnum := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
	}
	for i := 0; i <= len(hay); i++ {
		if i == len(hay) || !isAlnum(hay[i]) {
			if start >= 0 && hay[start:i] == kw {
				return true
			}
			start = -1
		} else if start < 0 {
			start = i
		}
	}
	return false
}

func detectPrintersIoT(p *Profile, devices []DeviceInfo) *Finding {
	score := 0.0
	var ind []string

	portSeen := map[uint32]bool{}
	for port := range p.SrcPorts {
		portSeen[port] = true
	}
	for port := range p.DestPorts {
		portSeen[port] = true
	}
	var iotHits []string
	for port := range portSeen {
		if containsU32(printerIotSignalPorts, port) {
			iotHits = append(iotHits, fmt.Sprint(port))
		}
	}
	sort.Strings(iotHits)
	if len(iotHits) > 0 {
		score += 0.2
		ind = append(ind, "IoT ports: "+strings.Join(iotHits, ", "))
	}

	if d := p.Duration(); d > 0 {
		if pps := float64(p.PacketCount) / d; pps < PrinterMaxPPS && p.PacketCount > 10 {
			score += 0.2
			ind = append(ind, fmt.Sprintf("very low rate: %.2f pps", pps))
		}
	}

	for _, dev := range devices {
		if dev.IP != p.IP {
			continue
		}
		vendor := strings.ToLower(dev.Vendor)
		osL := strings.ToLower(dev.OSGuess)
		host := strings.ToLower(dev.Hostname)

		matchAny := func(kws []string) bool {
			for _, kw := range kws {
				if kw == "hp" {
					// "hp" as a substring matches php/shop/etc.; require it
					// to be a standalone token.
					if hasToken(vendor, kw) || hasToken(host, kw) || hasToken(osL, kw) {
						return true
					}
					continue
				}
				if strings.Contains(vendor, kw) || strings.Contains(host, kw) || strings.Contains(osL, kw) {
					return true
				}
			}
			return false
		}
		if matchAny(printerKeywords) {
			score += 0.3
			v := dev.Vendor
			if v == "" {
				v = "?"
			}
			ind = append(ind, "printer detected: vendor="+v)
		}
		if matchAny(iotKeywords) {
			score += 0.25
			h := dev.Hostname
			if h == "" {
				h = "?"
			}
			ind = append(ind, "IoT device: host="+h)
		}
	}

	if p.DNSCount < 3 && p.PacketCount > 15 && p.UDPCount > p.TCPCount {
		score += 0.15
		ind = append(ind, "low DNS, UDP-dominant (typical of printers/IoT)")
	}
	if score >= FindingThreshold {
		return emit(p.IP, KPrinterIoT, minF(score, 1), ind)
	}
	return nil
}

// ── tiny numeric helpers ────────────────────────────────────────────────────

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
func sqrt(x float64) float64 { return math.Sqrt(x) }

func maxEntryU32(m map[uint32]uint64) (uint32, uint64) {
	var bp uint32
	var bc uint64
	first := true
	for p, c := range m {
		if first || c > bc || (c == bc && p < bp) {
			bp, bc = p, c
			first = false
		}
	}
	return bp, bc
}

func maxEntryStr(m map[string]uint64) (string, uint64) {
	var bk string
	var bc uint64
	first := true
	for k, c := range m {
		if first || c > bc || (c == bc && k < bk) {
			bk, bc = k, c
			first = false
		}
	}
	return bk, bc
}
