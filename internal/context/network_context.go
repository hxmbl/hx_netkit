// Package context builds the grounded network summary handed to the AI layer.
package context

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hxmbl/hx_netkit/internal/intel"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/textutil"
)

// NetworkContext bundles everything known about one capture.
type NetworkContext struct {
	Devices       []intel.DeviceInfo
	Findings      []intel.Finding
	Profiles      map[string]*intel.Profile
	CrossRef      string
	PacketCount   int
	Summaries     []intel.BehavioralSummary
	NmapSummaries []string
}

// Build loads a capture database and runs the full analysis pipeline.
func Build(db *store.DB, corporateMode bool) (*NetworkContext, error) {
	total := 0
	if err := db.QueryRow(`SELECT COUNT(*) FROM packets`).Scan(&total); err != nil {
		return nil, err
	}

	packets, err := intel.LoadPackets(db.DB)
	if err != nil {
		return nil, err
	}
	engine := intel.NewEngine()
	engine.IngestBatch(packets)

	deviceRows, err := db.Devices()
	if err != nil {
		return nil, err
	}
	devices := make([]intel.DeviceInfo, 0, len(deviceRows))
	for _, r := range deviceRows {
		deref := func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		}
		devices = append(devices, intel.DeviceInfo{
			IP:       r.IP,
			MAC:      deref(r.MAC),
			Hostname: deref(r.Hostname),
			Vendor:   deref(r.Vendor),
			OSGuess:  deref(r.OSGuess),
			Ports:    r.Ports,
		})
	}

	nmapSummaries, _ := db.NmapSummaries()

	findings := engine.Correlate(devices, corporateMode)
	crossRef := engine.CrossReference(devices)
	summaries := intel.GenerateNarratives(engine.Profiles(), devices, findings)

	return &NetworkContext{
		Devices:       devices,
		Findings:      findings,
		Profiles:      engine.Profiles(),
		CrossRef:      crossRef,
		PacketCount:   total,
		Summaries:     summaries,
		NmapSummaries: nmapSummaries,
	}, nil
}

// FormatForAI renders the context as markdown for the system/user prompt.
func (c *NetworkContext) FormatForAI() string {
	var parts []string

	totalDNS := 0
	for _, p := range c.Profiles {
		totalDNS += len(p.DNSDomains)
	}
	parts = append(parts, fmt.Sprintf(
		"## Overview\n%d packets, %d IPs, %d DNS domains, %d findings, %d devices",
		c.PacketCount, len(c.Profiles), totalDNS, len(c.Findings), len(c.Devices)))

	if len(c.Summaries) > 0 {
		var sb strings.Builder
		sb.WriteString("## What Each Device Is Doing\n")
		sb.WriteString("This is the behavioral analysis. Each device is described by what it's actually doing on the network.\n\n")
		for i, s := range c.Summaries {
			if i > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(s.String())
		}
		parts = append(parts, sb.String())
	}

	if len(c.Findings) > 0 {
		findings := append([]intel.Finding(nil), c.Findings...)
		sort.SliceStable(findings, func(i, j int) bool { return findings[i].Confidence > findings[j].Confidence })
		var lines []string
		for i, f := range findings {
			if i == 20 {
				break
			}
			detail := textutil.Truncate(f.Detail, 150)
			lines = append(lines, fmt.Sprintf("  %s [%s] %d%%: %s", f.IP, f.Kind, f.ConfidencePct(), detail))
		}
		parts = append(parts, "## Anomaly Signals\n"+
			"These are the detector findings. Each is a signal — cross-reference with behavioral narratives above.\n"+
			strings.Join(lines, "\n"))
	}

	type prof struct {
		ip string
		p  *intel.Profile
	}
	profiles := make([]prof, 0, len(c.Profiles))
	for ip, p := range c.Profiles {
		profiles = append(profiles, prof{ip, p})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].p.PacketCount > profiles[j].p.PacketCount })
	if len(profiles) > 0 {
		var lines []string
		for i, pr := range profiles {
			if i == 15 {
				break
			}
			p := pr.p
			duration := p.Duration()
			pps := 0.0
			if duration > 0 {
				pps = float64(p.PacketCount) / duration
			}
			domains := ""
			if top := p.TopDNS(3); len(top) > 0 {
				strs := make([]string, len(top))
				for j, d := range top {
					strs[j] = fmt.Sprintf("%s(%d)", d.Domain, d.Count)
				}
				domains = ", top domains: " + strings.Join(strs, ", ")
			}
			ports := ""
			if top := p.TopDestPorts(3); len(top) > 0 {
				strs := make([]string, len(top))
				for j, pt := range top {
					strs[j] = fmt.Sprintf("%d/%d", pt.Port, pt.Count)
				}
				ports = ", top ports: " + strings.Join(strs, ", ")
			}
			lines = append(lines, fmt.Sprintf("  %s: %d pkts (%d↑ %d↓, %.1fs, %.1f pps)%s%s",
				pr.ip, p.PacketCount, p.OutboundCount, p.InboundCount, duration, pps, domains, ports))
		}
		parts = append(parts, "## Top Talkers (raw stats)\n"+strings.Join(lines, "\n"))
	}

	if c.CrossRef != "" {
		parts = append(parts, "## Cross-Reference (nmap ↔ traffic)\n"+
			"Matches devices discovered by nmap with their traffic behavior.\n"+c.CrossRef)
	}

	return strings.Join(parts, "\n\n")
}
