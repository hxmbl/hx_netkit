// Package belief implements a lightweight Bayesian tracker that maintains a
// 5-category probability distribution (BOT, IOT, CAM, CLEAN, UNKNOWN) per IP
// and updates it as nmap evidence arrives.
package belief

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/hxmbl/hx_netkit/internal/intel"
)

// Category is one hypothesis about what an IP is.
type Category int

const (
	Bot Category = iota
	IoT
	Camera
	Clean
	Unknown
)

var allCategories = []Category{Bot, IoT, Camera, Clean, Unknown}

func (c Category) String() string {
	switch c {
	case Bot:
		return "BOT"
	case IoT:
		return "IOT"
	case Camera:
		return "CAM"
	case Clean:
		return "CLN"
	default:
		return "UNK"
	}
}

// IPBelief is the current distribution for one IP.
type IPBelief struct {
	IP        string
	Dist      map[Category]float64
	Entropy   float64
	MaxCat    Category
	MaxProb   float64
	Scanned   bool
	ScanCount uint32
}

// System holds beliefs for all tracked IPs.
type System struct {
	beliefs map[string]*IPBelief
}

// New creates an empty system.
func New() *System { return &System{beliefs: map[string]*IPBelief{}} }

// Len returns number of tracked IPs.
func (s *System) Len() int { return len(s.beliefs) }

// Has reports whether ip is tracked.
func (s *System) Has(ip string) bool { _, ok := s.beliefs[ip]; return ok }

// Get returns the belief for ip.
func (s *System) Get(ip string) (*IPBelief, bool) {
	b, ok := s.beliefs[ip]
	return b, ok
}

func categoryForKind(k intel.Kind) Category {
	switch k {
	case intel.KBot, intel.KC2Beacon, intel.KBeacon, intel.KScanner,
		intel.KLateralMovement, intel.KNetworkRecon, intel.KDataExfil,
		intel.KDNSProfiler:
		return Bot
	case intel.KIoTDevice, intel.KPrinterIoT:
		return IoT
	case intel.KBrowser, intel.KServer, intel.KStreamingMedia,
		intel.KCloudSync, intel.KGameClient:
		return Clean
	default: // VPN, Tor, IoTCoordinator, Unknown
		return Unknown
	}
}

// InitializeFromFindings seeds beliefs from detector output.
func (s *System) InitializeFromFindings(findings []intel.Finding) {
	for _, f := range findings {
		primary := categoryForKind(f.Kind)
		primaryProb := f.Confidence * 0.8
		residual := 1 - primaryProb
		unknownProb := residual * 0.4
		otherCount := 3
		otherProb := 0.0
		if otherCount > 0 && residual-unknownProb > 0 {
			otherProb = (residual - unknownProb) / float64(otherCount)
		}

		dist := map[Category]float64{}
		for _, cat := range allCategories {
			switch cat {
			case primary:
				dist[cat] = primaryProb
			case Unknown:
				dist[cat] = unknownProb
			default:
				dist[cat] = otherProb
			}
		}
		normalize(dist)

		s.beliefs[f.IP] = &IPBelief{
			IP:      f.IP,
			Dist:    dist,
			Entropy: entropy(dist),
			MaxCat:  maxOf(dist),
			MaxProb: dist[maxOf(dist)],
			Scanned: false,
		}
	}
}

// Ensure adds ip with the default prior if not already tracked.
func (s *System) Ensure(ip string) {
	if _, ok := s.beliefs[ip]; ok {
		return
	}
	dist := map[Category]float64{}
	for _, cat := range allCategories {
		switch cat {
		case Clean:
			dist[cat] = 0.50
		case Unknown:
			dist[cat] = 0.40
		default:
			dist[cat] = 0.025
		}
	}
	normalize(dist)
	s.beliefs[ip] = &IPBelief{
		IP:      ip,
		Dist:    dist,
		Entropy: entropy(dist),
		MaxCat:  maxOf(dist),
		MaxProb: dist[maxOf(dist)],
	}
}

// PriorityIP picks the unscanned (or least-scanned) IP with the highest
// uncertainty, capped at maxScans per IP. Returns ok=false when nothing needs
// scanning.
func (s *System) PriorityIP(maxScans uint32) (ip string, ent float64, ok bool) {
	bestEnt := -1.0
	for _, b := range s.beliefs {
		if b.ScanCount >= maxScans || b.MaxProb >= 0.90 {
			continue
		}
		if b.Entropy > bestEnt {
			bestEnt = b.Entropy
			ip = b.IP
			ent = b.Entropy
			ok = true
		}
	}
	return ip, ent, ok
}

// UpdateFromNmap folds scan evidence into the belief for ip.
func (s *System) UpdateFromNmap(ip string, alive bool, openPorts []uint32) {
	b, exists := s.beliefs[ip]
	if !exists {
		return
	}
	dist := copyDist(b.Dist)

	iotPorts := []uint32{5353, 1900, 5355, 5683, 5684, 8883, 1883, 9100, 631}
	camPorts := []uint32{554, 1935, 8554, 1024, 1025}
	hasIot := false
	for _, p := range openPorts {
		for _, q := range iotPorts {
			if p == q {
				hasIot = true
			}
		}
	}
	hasCam := false
	for _, p := range openPorts {
		for _, q := range camPorts {
			if p == q {
				hasCam = true
			}
		}
	}

	for _, cat := range allCategories {
		prob := dist[cat]
		switch {
		case alive && len(openPorts) > 0:
			switch cat {
			case Clean:
				prob *= 1.3
			case IoT:
				if hasIot {
					prob *= 2.0
				} else {
					prob *= 0.9
				}
			case Camera:
				if hasCam {
					prob *= 2.0
				} else {
					prob *= 0.9
				}
			default:
				prob *= 0.9
			}
		case alive:
			switch cat {
			case Unknown:
				prob *= 1.2
			case Clean:
				prob *= 1.1
			default:
				prob *= 0.95
			}
		default:
			switch cat {
			case Unknown:
				prob *= 1.3
			case Bot:
				prob *= 0.8
			}
		}
		dist[cat] = prob
	}

	normalize(dist)
	b.Dist = dist
	b.Entropy = entropy(dist)
	mc := maxOf(dist)
	b.MaxCat = mc
	b.MaxProb = dist[mc]
	b.Scanned = true
	b.ScanCount++
}

// FormatAll renders every belief sorted by descending uncertainty.
func (s *System) FormatAll() string {
	type row struct {
		name string
		line string
	}
	var rows []row
	for _, b := range s.beliefs {
		var cats []string
		for _, cat := range allCategories {
			cats = append(cats, fmt.Sprintf("%s:%.0f%%", cat, b.Dist[cat]*100))
		}
		marker := ""
		if b.Scanned {
			marker = " 🔍"
		}
		rows = append(rows, row{b.IP, fmt.Sprintf("  %-16s %5.2f bits [%s]%s", b.IP, b.Entropy, strings.Join(cats, ", "), marker)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.line
	}
	return strings.Join(lines, "\n")
}

// FormatIP renders one IP's belief line, if tracked.
func (s *System) FormatIP(ip string) (string, bool) {
	b, ok := s.beliefs[ip]
	if !ok {
		return "", false
	}
	var cats []string
	for _, cat := range allCategories {
		cats = append(cats, fmt.Sprintf("%s: %.0f%%", cat, b.Dist[cat]*100))
	}
	scanned := ""
	if b.Scanned {
		scanned = " (scanned)"
	}
	return fmt.Sprintf("IP %s: entropy %.2f bits [%s]%s", b.IP, b.Entropy, strings.Join(cats, ", "), scanned), true
}

func normalize(dist map[Category]float64) {
	sum := 0.0
	for _, v := range dist {
		sum += v
	}
	if sum > 0 {
		for k, v := range dist {
			dist[k] = v / sum
		}
	}
}

func entropy(dist map[Category]float64) float64 {
	e := 0.0
	for _, p := range dist {
		if p > 0 {
			e -= p * math.Log2(p)
		}
	}
	return e
}

func maxOf(dist map[Category]float64) Category {
	best := Unknown
	bestP := math.Inf(-1)
	for _, cat := range allCategories {
		if p := dist[cat]; p > bestP {
			bestP = p
			best = cat
		}
	}
	return best
}

func copyDist(d map[Category]float64) map[Category]float64 {
	out := make(map[Category]float64, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}
