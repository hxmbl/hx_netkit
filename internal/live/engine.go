// Package live implements real-time packet interpretation without AI:
// a streaming classifier that labels each active IP as traffic arrives.
package live

import (
	"fmt"
	"sort"
	"strings"
)

// PortService maps well-known ports to friendly service names.
var portService = map[uint16]string{
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	3306:  "MySQL",
	3389:  "RDP",
	5000:  "UPnP/DLNA",
	5353:  "mDNS",
	8008:  "Chromecast",
	8009:  "Chromecast",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	9100:  "Printer",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
}

// ServiceName returns the friendly name for a port or "?".
func ServiceName(port uint16) string {
	if s, ok := portService[port]; ok {
		return s
	}
	return "?"
}

type ipRole struct {
	ip          string
	role        string
	detail      string
	confidence  float64
	ports       []uint16
	dnsQueries  []string
	packetCount uint64
	firstSeen   float64
	lastSeen    float64
}

// Engine classifies IPs from a live packet stream.
type Engine struct {
	roles  map[string]*ipRole
	dnsMap map[string][]string
}

// NewEngine creates an empty interpretation engine.
func NewEngine() *Engine {
	return &Engine{
		roles:  map[string]*ipRole{},
		dnsMap: map[string][]string{},
	}
}

func isMulticast(ip string) bool {
	return strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") || ip == "255.255.255.255"
}

// ProcessPacket folds one packet into the engine state.
func (e *Engine) ProcessPacket(epoch float64, src, dst string, tcpDst *uint16, dnsQry string) {
	if isMulticast(dst) || isMulticast(src) {
		return
	}

	srcRole := e.ensure(src, epoch)
	srcRole.packetCount++
	srcRole.lastSeen = maxF(srcRole.lastSeen, epoch)
	if tcpDst != nil && !containsPort(srcRole.ports, *tcpDst) {
		srcRole.ports = append(srcRole.ports, *tcpDst)
	}
	if dnsQry != "" {
		srcRole.dnsQueries = append(srcRole.dnsQueries, dnsQry)
		e.dnsMap[src] = append(e.dnsMap[src], dnsQry)
	}

	dstRole := e.ensure(dst, epoch)
	dstRole.packetCount++
	if tcpDst != nil {
		if svc, ok := portService[*tcpDst]; ok {
			dstRole.detail = fmt.Sprintf("serves %s (%d)", svc, *tcpDst)
			dstRole.confidence = 0.7
		}
	}
	if dnsQry != "" {
		dstRole.detail = fmt.Sprintf("queries %s", dnsQry)
		dstRole.confidence = 0.6
	}
}

func (e *Engine) ensure(ip string, epoch float64) *ipRole {
	r, ok := e.roles[ip]
	if !ok {
		r = &ipRole{ip: ip, role: "unknown", firstSeen: epoch, lastSeen: epoch}
		e.roles[ip] = r
		return r
	}
	r.lastSeen = maxF(r.lastSeen, epoch)
	return r
}

// Interpretation pairs an IP with its rendered description.
type Interpretation struct {
	IP   string
	Desc string
}

// Interpret ranks the top 20 most active IPs with heuristic labels.
func (e *Engine) Interpret() []Interpretation {
	type entry struct {
		ip string
		r  *ipRole
	}
	list := make([]entry, 0, len(e.roles))
	for ip, r := range e.roles {
		list = append(list, entry{ip, r})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].r.packetCount > list[j].r.packetCount })

	var out []Interpretation
	for i, en := range list {
		if i == 20 {
			break
		}
		r := en.r
		var b strings.Builder
		fmt.Fprintf(&b, "[%s]", en.ip)

		has := func(p uint16) bool { return containsPort(r.ports, p) }
		switch {
		case has(80) || has(443):
			if has(22) {
				b.WriteString(" — server (HTTP + SSH)")
			} else {
				b.WriteString(" — device on web")
			}
		case has(8008) || has(8009):
			b.WriteString(" — Chromecast")
		case has(5353):
			b.WriteString(" — mDNS device")
		case has(5000):
			b.WriteString(" — UPnP/DLNA device")
		case has(9100):
			b.WriteString(" — printer")
		case has(22):
			b.WriteString(" — Linux/Mac device")
		case len(r.dnsQueries) > 3:
			b.WriteString(" — active browser")
		case r.packetCount > 100:
			b.WriteString(" — high-traffic device")
		default:
			b.WriteString(" — IoT/embedded")
		}

		if uniq := uniqueStrings(r.dnsQueries); len(uniq) > 0 {
			top := uniq
			if len(top) > 3 {
				top = top[:3]
			}
			fmt.Fprintf(&b, " | dns: %s", strings.Join(top, ", "))
		}
		fmt.Fprintf(&b, " | %d pkts", r.packetCount)
		out = append(out, Interpretation{IP: en.ip, Desc: b.String()})
	}
	return out
}

func containsPort(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
