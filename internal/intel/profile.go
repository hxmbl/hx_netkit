package intel

import (
	"database/sql"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
)

// maxRetainedPackets bounds the engine's packet buffer. Cross-reference
// evidence only needs recent samples; retaining everything would exhaust
// memory on large captures.
const maxRetainedPackets = 50000

// Packet is a normalized frame used throughout analysis.
type Packet struct {
	Epoch    float64
	SrcIP    string
	DstIP    string
	TCPsrc   uint32
	TCPdst   uint32
	UDPsrc   uint32
	UDPdst   uint32
	DNSQuery string
	FrameLen uint32
}

func (p Packet) hasTCP() bool { return p.TCPsrc > 0 || p.TCPdst > 0 }
func (p Packet) hasUDP() bool { return p.UDPsrc > 0 || p.UDPdst > 0 }
func (p Packet) dstPort() uint32 {
	if p.TCPdst > 0 {
		return p.TCPdst
	}
	return p.UDPdst
}
func (p Packet) srcPort() uint32 {
	if p.TCPsrc > 0 {
		return p.TCPsrc
	}
	return p.UDPsrc
}

// TCPSession tracks a unidirectional flow keyed by (src, sport, dst, dport).
type TCPSession struct {
	Src, Dst            string
	SrcPort, DstPort    uint32
	FirstPacket         float64
	LastPacket          float64
	PktCount            uint64
	BytesApprox         uint64
	SynSeen, SynAckSeen bool
	FinSeen, RstSeen    bool
}

type temporalBin struct {
	start, end float64
	count      uint64
}

// Profile is the per-IP behavioral fingerprint built by ingestion.
type Profile struct {
	IP          string
	FirstSeen   float64
	LastSeen    float64
	PacketCount uint64

	DestIPs           map[string]uint64
	SrcIPs            map[string]uint64
	DestPorts         map[uint32]uint64
	SrcPorts          map[uint32]uint64
	UniqueConnections int64

	Sessions map[string]*TCPSession

	DNSQueries      []string
	DNSDomains      map[string]uint64
	DNSSingleLabels uint64

	TCPCount, UDPCount, DNSCount, ICMPCount uint64

	InboundCount, OutboundCount uint64
	InboundBytes, OutboundBytes uint64

	temporalBins      []temporalBin
	interArrivalTimes []float64

	DestPortEntropy float64
	SrcPortEntropy  float64

	wellKnownPorts, ephemeralPorts, privilegedPorts []uint32

	PacketSizeVariance float64
	m2                 float64 // streaming sum of squared deviations (Welford)
	AvgPacketSize      float64
	BurstScore         float64
}

func newProfile(ip string) *Profile {
	return &Profile{
		IP:         ip,
		FirstSeen:  math.MaxFloat64,
		LastSeen:   math.SmallestNonzeroFloat64,
		DestIPs:    map[string]uint64{},
		SrcIPs:     map[string]uint64{},
		DestPorts:  map[uint32]uint64{},
		SrcPorts:   map[uint32]uint64{},
		Sessions:   map[string]*TCPSession{},
		DNSDomains: map[string]uint64{},
	}
}

func (p *Profile) ingest(pkt Packet) {
	p.PacketCount++
	if pkt.Epoch < p.FirstSeen {
		p.FirstSeen = pkt.Epoch
	}
	if pkt.Epoch > p.LastSeen {
		p.LastSeen = pkt.Epoch
	}

	isSrc := pkt.SrcIP == p.IP
	isDst := pkt.DstIP == p.IP

	if isSrc {
		p.OutboundCount++
		if pkt.DstIP != "" {
			p.DestIPs[pkt.DstIP]++
		}
		if dp := pkt.dstPort(); dp > 0 {
			p.DestPorts[dp]++
		}
	}
	if isDst {
		p.InboundCount++
		if pkt.SrcIP != "" {
			p.SrcIPs[pkt.SrcIP]++
		}
		if sp := pkt.srcPort(); sp > 0 {
			p.SrcPorts[sp]++
		}
	}

	// Session tracking (TCP flows).
	if pkt.TCPsrc > 0 && pkt.TCPdst > 0 && pkt.SrcIP != "" && pkt.DstIP != "" {
		key := sessionKey(pkt.SrcIP, pkt.TCPsrc, pkt.DstIP, pkt.TCPdst)
		s, ok := p.Sessions[key]
		if !ok {
			s = &TCPSession{
				Src: pkt.SrcIP, Dst: pkt.DstIP,
				SrcPort: pkt.TCPsrc, DstPort: pkt.TCPdst,
				FirstPacket: pkt.Epoch,
			}
			p.Sessions[key] = s
		}
		s.LastPacket = pkt.Epoch
		s.PktCount++
		bytes := uint64(pkt.FrameLen)
		if bytes == 0 {
			bytes = MTUSmall
		}
		s.BytesApprox += bytes
	}

	if pkt.hasTCP() {
		p.TCPCount++
	}
	if pkt.hasUDP() {
		p.UDPCount++
	}

	if q := pkt.DNSQuery; q != "" {
		p.DNSCount++
		p.DNSQueries = append(p.DNSQueries, q)
		p.DNSDomains[ExtractDomain(q)]++
		if strings.Count(q, ".") == 0 {
			p.DNSSingleLabels++
		}
	}

	p.interArrivalTimes = append(p.interArrivalTimes, pkt.Epoch)

	if fl := pkt.FrameLen; fl > 0 {
		n := float64(p.PacketCount)
		delta := float64(fl) - p.AvgPacketSize
		p.AvgPacketSize += delta / n
		p.m2 += delta * (float64(fl) - p.AvgPacketSize)
		if n > 1 {
			v := p.m2 / (n - 1)
			if v < 0 {
				v = 0
			}
			p.PacketSizeVariance = v
		}
		if isSrc {
			p.OutboundBytes += uint64(fl)
		}
		if isDst {
			p.InboundBytes += uint64(fl)
		}
	}

	binStart := math.Floor(pkt.Epoch)
	if n := len(p.temporalBins); n > 0 && p.temporalBins[n-1].start == binStart {
		p.temporalBins[n-1].count++
		if pkt.Epoch > p.temporalBins[n-1].end {
			p.temporalBins[n-1].end = pkt.Epoch
		}
	} else {
		p.temporalBins = append(p.temporalBins, temporalBin{start: binStart, end: pkt.Epoch, count: 1})
	}
}

func sessionKey(src string, sport uint32, dst string, dport uint32) string {
	// '#' cannot appear in hostnames or ports, so the key stays unambiguous
	// even for exotic inputs (e.g. IPv6 literals containing ':').
	var b strings.Builder
	b.WriteString(src)
	b.WriteByte('#')
	b.WriteString(strconv.FormatUint(uint64(sport), 10))
	b.WriteString("->")
	b.WriteString(dst)
	b.WriteByte('#')
	b.WriteString(strconv.FormatUint(uint64(dport), 10))
	return b.String()
}

func (p *Profile) finalize() {
	p.DestPortEntropy = portSetEntropy(p.DestPorts)
	p.SrcPortEntropy = portSetEntropy(p.SrcPorts)

	for port := range p.SrcPorts {
		switch {
		case port < PrivilegedPortMax:
			p.privilegedPorts = append(p.privilegedPorts, port)
		case port >= EphemeralPortMin:
			p.ephemeralPorts = append(p.ephemeralPorts, port)
		default:
			p.wellKnownPorts = append(p.wellKnownPorts, port)
		}
	}

	p.UniqueConnections = int64(len(p.Sessions) + len(p.DestIPs) + len(p.SrcIPs))

	if len(p.temporalBins) >= MinBinsForBurst {
		var total float64
		for _, b := range p.temporalBins {
			total += float64(b.count)
		}
		mean := total / float64(len(p.temporalBins))
		if mean > 0 {
			var variance float64
			for _, b := range p.temporalBins {
				d := float64(b.count) - mean
				variance += d * d
			}
			variance /= float64(len(p.temporalBins))
			p.BurstScore = math.Sqrt(variance) / mean
		}
	}
}

// Duration returns seconds between first and last packet.
func (p *Profile) Duration() float64 { return p.LastSeen - p.FirstSeen }

// PPS returns average packets per second over the profile lifetime.
func (p *Profile) PPS() float64 {
	if d := p.Duration(); d > 0 {
		return float64(p.PacketCount) / d
	}
	return 0
}

// TopDNS returns up to n (domain, count) pairs sorted by count desc.
func (p *Profile) TopDNS(n int) []DomainCount { return topOfMap(p.DNSDomains, n) }

// TopDestPorts returns up to n (port, count) pairs sorted by count desc.
func (p *Profile) TopDestPorts(n int) []PortCount { return topOfMapU32(p.DestPorts, n) }

// InternalDestCount counts distinct private destinations contacted.
func (p *Profile) InternalDestCount() int {
	n := 0
	for ip := range p.DestIPs {
		if IsPrivateIP(ip) {
			n++
		}
	}
	return n
}

// ExternalDestCount counts distinct public destinations contacted.
func (p *Profile) ExternalDestCount() int {
	n := 0
	for ip := range p.DestIPs {
		if !IsPrivateIP(ip) {
			n++
		}
	}
	return n
}

type DomainCount struct {
	Domain string
	Count  uint64
}
type PortCount struct {
	Port  uint32
	Count uint64
}

func topOfMap(m map[string]uint64, n int) []DomainCount {
	out := make([]DomainCount, 0, len(m))
	for k, v := range m {
		out = append(out, DomainCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topOfMapU32(m map[uint32]uint64, n int) []PortCount {
	out := make([]PortCount, 0, len(m))
	for k, v := range m {
		out = append(out, PortCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Port < out[j].Port
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// portSetEntropy returns the entropy of the distinct-port distribution.
// Because each key in the map occurs exactly once, this equals log2(n):
// maximal spread across n distinct ports.
func portSetEntropy(m map[uint32]uint64) float64 {
	if len(m) == 0 {
		return 0
	}
	return math.Log2(float64(len(m)))
}

// ShannonEntropy computes binary entropy of a value distribution.
func ShannonEntropy(values []uint32) float64 {
	if len(values) == 0 {
		return 0
	}
	total := float64(len(values))
	freq := map[uint32]float64{}
	for _, v := range values {
		freq[v]++
	}
	e := 0.0
	for _, c := range freq {
		pr := c / total
		e -= pr * math.Log2(pr)
	}
	return e
}

func shannonEntropy(m map[uint32]uint64) float64 {
	if len(m) == 0 {
		return 0
	}
	total := float64(len(m))
	e := 0.0
	for _, c := range m {
		pr := float64(c) / total
		e -= pr * math.Log2(pr)
	}
	return e
}

// ExtractDomain reduces an FQDN to its registrable two-label suffix.
func ExtractDomain(fqdn string) string {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return fqdn
}

// IsPrivateIP reports whether ip falls in private, loopback, or link-local
// space. IPv4 uses RFC1918 rules; IPv6 is handled via net.IP classification
// so ::1, fe80::/10 and ULA addresses are treated as internal too.
func IsPrivateIP(ip string) bool {
	if strings.Contains(ip, ":") {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return false
		}
		return parsed.IsLoopback() || parsed.IsPrivate() ||
			parsed.IsLinkLocalUnicast() || parsed.IsUnspecified()
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	o := make([]int, 4)
	for i, s := range parts {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 || v > 255 {
			return false
		}
		o[i] = v
	}
	switch o[0] {
	case 10:
		return true
	case 172:
		return o[1] >= 16 && o[1] <= 31
	case 192:
		return o[1] == 168
	case 169:
		return o[1] == 254
	case 127:
		return true // loopback
	}
	return false
}

// LoadPackets reads all packets from a capture DB ordered by time.
func LoadPackets(db *sql.DB) ([]Packet, error) {
	rows, err := db.Query(`SELECT epoch, ip_src, ip_dst, tcp_src_port, tcp_dst_port,
		udp_src_port, udp_dst_port, dns_query, COALESCE(frame_len, 0)
		FROM packets ORDER BY epoch`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Packet
	for rows.Next() {
		var p Packet
		var src, dst, dns sql.NullString
		var tcps, tcpd, udps, udpd, fl sql.NullInt64
		var epoch sql.NullFloat64
		if err := rows.Scan(&epoch, &src, &dst, &tcps, &tcpd, &udps, &udpd, &dns, &fl); err != nil {
			continue
		}
		p.Epoch = epoch.Float64
		p.SrcIP = src.String
		p.DstIP = dst.String
		p.TCPsrc = nullUint32(tcps)
		p.TCPdst = nullUint32(tcpd)
		p.UDPsrc = nullUint32(udps)
		p.UDPdst = nullUint32(udpd)
		p.DNSQuery = dns.String
		p.FrameLen = uint32(fl.Int64)
		out = append(out, p)
	}
	return out, rows.Err()
}

func nullUint32(v sql.NullInt64) uint32 {
	if !v.Valid || v.Int64 < 0 {
		return 0
	}
	return uint32(v.Int64)
}
