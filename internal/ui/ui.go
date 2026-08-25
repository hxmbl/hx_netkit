// Package ui renders terminal output for the correlator CLI: severity-coded
// findings, confidence bars, status symbols, and live progress lines.
//
// Color is governed by the caller (TTY detection) and additionally by
// NO_COLOR/termenv — lipgloss degrades to plain text automatically.
package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/hxmbl/hx_netkit/internal/intel"
)

// Severity buckets drive ordering and color.
type Severity int

const (
	SevCritical Severity = iota // C2, exfil, lateral movement
	SevWarning                  // bot/scanner/beacon/recon/tor/dns-profiling
	SevInfo                     // VPN and ambiguous tooling
	SevBenign                   // known-good device classes
	SevUnknown
)

func severityOf(k intel.Kind) Severity {
	switch k {
	case intel.KC2Beacon, intel.KDataExfil, intel.KLateralMovement:
		return SevCritical
	case intel.KBot, intel.KScanner, intel.KBeacon, intel.KNetworkRecon,
		intel.KTor, intel.KDNSProfiler:
		return SevWarning
	case intel.KVPN:
		return SevInfo
	case intel.KServer, intel.KBrowser, intel.KIoTDevice, intel.KPrinterIoT,
		intel.KStreamingMedia, intel.KCloudSync, intel.KGameClient,
		intel.KIoTCoordinator:
		return SevBenign
	default:
		return SevUnknown
	}
}

var severityNames = map[Severity]string{
	SevCritical: "critical",
	SevWarning:  "warning",
	SevInfo:     "info",
	SevBenign:   "benign",
	SevUnknown:  "unknown",
}

func (s Severity) String() string { return severityNames[s] }

// IsThreatKind reports whether a kind represents potentially malicious behavior.
func IsThreatKind(k intel.Kind) bool { return severityOf(k) <= SevWarning }

var (
	styleCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))
	styleBenign   = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleDim      = lipgloss.NewStyle().Faint(true)
	styleBarFill  = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
)

func styleFor(s Severity) lipgloss.Style {
	switch s {
	case SevCritical:
		return styleCritical
	case SevWarning:
		return styleWarn
	case SevInfo:
		return styleInfo
	case SevBenign:
		return styleBenign
	default:
		return styleDim
	}
}

// ── Findings rendering ──────────────────────────────────────────────────────

// FindingsOptions tunes RenderFindings.
type FindingsOptions struct {
	Color           bool
	MinConfidencePc int    // drop findings below this percent
	TopN            int    // keep at most N findings overall (0 = all)
	KindFilter      string // all | threat | benign | comma-separated KIND names
	Indicators      int    // indicator lines per finding (default 2)
}

var groupOrder = []intel.Kind{
	intel.KC2Beacon, intel.KDataExfil, intel.KLateralMovement,
	intel.KBot, intel.KScanner, intel.KBeacon, intel.KNetworkRecon,
	intel.KTor, intel.KDNSProfiler, intel.KVPN,
	intel.KServer, intel.KBrowser, intel.KIoTCoordinator,
	intel.KPrinterIoT, intel.KIoTDevice,
	intel.KStreamingMedia, intel.KCloudSync, intel.KGameClient, intel.KUnknown,
}

// ParseKindFilter validates a --kind value against known names/classes.
func ParseKindFilter(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "all" || v == "threat" || v == "benign" {
		return v, nil
	}
	for _, part := range strings.Split(v, ",") {
		name := strings.ToUpper(strings.TrimSpace(part))
		found := false
		for k := intel.KBrowser; k <= intel.KUnknown; k++ {
			if k.String() == name {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("unknown kind %q; use threat, benign, all, or names like SCANNER,C2_BEACON", part)
		}
	}
	return v, nil
}

func matchesKindFilter(f intel.Finding, filter string) bool {
	switch filter {
	case "", "all":
		return true
	case "threat":
		return IsThreatKind(f.Kind)
	case "benign":
		return severityOf(f.Kind) >= SevBenign
	default:
		for _, part := range strings.Split(filter, ",") {
			if strings.EqualFold(strings.TrimSpace(part), f.Kind.String()) {
				return true
			}
		}
		return false
	}
}

// Bar renders a 10-cell confidence bar.
func Bar(conf float64, color bool) string {
	cells := int(conf*10 + 0.5)
	if cells < 0 {
		cells = 0
	}
	if cells > 10 {
		cells = 10
	}
	bar := strings.Repeat("█", cells) + strings.Repeat("░", 10-cells)
	if color {
		bar = styleBarFill.Render(bar)
	}
	return bar
}

// Status symbols for doctor-style checklists.
type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusFail
)

func (s Status) String(color bool) string {
	switch s {
	case StatusOK:
		if color {
			return styleBenign.Render("✔")
		}
		return "ok"
	case StatusWarn:
		if color {
			return styleWarn.Render("⚠")
		}
		return "warn"
	default:
		if color {
			return styleCritical.Render("✘")
		}
		return "FAIL"
	}
}

// FilterFindings applies confidence/kind/top-N selection.
func FilterFindings(fs []intel.Finding, opt FindingsOptions) []intel.Finding {
	filtered := make([]intel.Finding, 0, len(fs))
	for _, f := range fs {
		if f.ConfidencePct() < opt.MinConfidencePc {
			continue
		}
		if !matchesKindFilter(f, opt.KindFilter) {
			continue
		}
		filtered = append(filtered, f)
	}
	if opt.TopN > 0 && len(filtered) > opt.TopN {
		sorted := append([]intel.Finding(nil), filtered...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Confidence > sorted[j].Confidence })
		filtered = sorted[:opt.TopN]
	}
	return filtered
}

// RenderFindings writes grouped, optionally colored findings.
func RenderFindings(w io.Writer, fs []intel.Finding, opt FindingsOptions) {
	filtered := FilterFindings(fs, opt)
	if len(filtered) == 0 {
		fmt.Fprintln(w, "(no findings match)")
		return
	}

	indicators := opt.Indicators
	if indicators == 0 {
		indicators = 2
	}

	byKind := map[intel.Kind][]intel.Finding{}
	kinds := []intel.Kind{}
	for _, f := range filtered {
		if _, seen := byKind[f.Kind]; !seen {
			kinds = append(kinds, f.Kind)
		}
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	sortKindsByOrder(kinds)

	for _, k := range kinds {
		group := byKind[k]
		label := k.String()
		sev := severityOf(k)
		if opt.Color {
			label = styleFor(sev).Render(label)
		}
		fmt.Fprintf(w, "\n── %s · %s (%d) ──\n", label, sev, len(group))
		for _, f := range group {
			pct := f.ConfidencePct()
			detail := f.Detail
			fmt.Fprintf(w, "  %-16s %s %3d%%  %s\n", f.IP, Bar(f.Confidence, opt.Color), pct, detail)
			for i, ind := range f.Indicators {
				if i == indicators {
					break
				}
				fmt.Fprintf(w, "  %-16s       → %s\n", "", ind)
			}
		}
	}
}

func sortKindsByOrder(kinds []intel.Kind) {
	rank := func(k intel.Kind) int {
		for i, want := range groupOrder {
			if k == want {
				return i
			}
		}
		return len(groupOrder)
	}
	for i := 1; i < len(kinds); i++ {
		for j := i; j > 0 && rank(kinds[j]) < rank(kinds[j-1]); j-- {
			kinds[j], kinds[j-1] = kinds[j-1], kinds[j]
		}
	}
}

// ── Progress line ───────────────────────────────────────────────────────────

// Progress renders a single-line capture progress meter, throttled so it
// updates at most every interval even when fed every packet.
type Progress struct {
	Label    string
	Total    time.Duration
	interval time.Duration
	last     time.Time
	start    time.Time
	out      io.Writer
}

// NewProgress builds a meter writing to w.
func NewProgress(out io.Writer, label string, total time.Duration) *Progress {
	now := time.Now()
	return &Progress{
		Label:    label,
		Total:    total,
		interval: 400 * time.Millisecond,
		start:    now,
		last:     now,
		out:      out,
	}
}

// MaybeRender redraws the meter if the throttle window elapsed. Returns true
// when it drew.
func (p *Progress) MaybeRender(count uint64, bytes uint64) bool {
	now := time.Now()
	if now.Sub(p.last) < p.interval {
		return false
	}
	p.last = now
	elapsed := now.Sub(p.start).Seconds()
	pps := 0.0
	if elapsed > 0 {
		pps = float64(count) / elapsed
	}
	remaining := p.Total - time.Duration(elapsed*float64(time.Second))
	if remaining < 0 {
		remaining = 0
	}
	fmt.Fprintf(p.out, "\r\x1b[K  %s %s pkts · %.1f MB · %.0f pps · %s/%s elapsed ",
		p.Label, humanCount(count), float64(bytes)/1_048_576, pps,
		formatDur(now.Sub(p.start)), formatDur(remaining))
	return true
}

// Finish clears the meter line.
func (p *Progress) Finish() {
	fmt.Fprint(p.out, "\r\x1b[K")
}

func humanCount(n uint64) string {
	s := fmt.Sprintf("%d", n)
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	return strings.Join(parts, ",")
}

func formatDur(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 0 {
		secs = 0
	}
	m := secs / 60
	s := secs % 60
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
