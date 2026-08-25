// Package tshark parses TShark "ek" (JSON per line) output into packets
// and builds the argument vectors used to drive the TShark CLI.
package tshark

import (
	"encoding/json"
	"strings"
)

// Packet is one decoded TShark frame.
type Packet struct {
	Epoch    float64
	IPSrc    string
	IPDst    string
	TCPsrc   uint32 // 0 when absent
	TCPdst   uint32
	UDPsrc   uint32
	UDPdst   uint32
	DNSQuery string
	FrameLen uint32
	HasEpoch bool
}

// Fields mirrors the -e field list in Args.
var fields = []string{
	"frame.time_epoch",
	"frame.len",
	"ip.src",
	"ip.dst",
	"tcp.srcport",
	"tcp.dstport",
	"udp.srcport",
	"udp.dstport",
	"dns.qry.name",
}

// Args returns the standard TShark argument vector for ek JSON extraction.
func Args(interface_, filter string) []string {
	if strings.TrimSpace(filter) == "" {
		filter = "not host 127.0.0.1"
	}
	args := []string{"-i", interface_, "-n", "-l", "-T", "ek", "-f", filter}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	return args
}

// ParseLine decodes a single line of TShark ek output. It accepts both the
// nested "_source.layers" form and the flat "layers" object form; values may
// be strings or single-element arrays. It returns ok=false for index/metadata
// lines and unparseable input.
func ParseLine(line string) (Packet, bool) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Packet{}, false
	}

	layers := findLayers(raw)
	if layers == nil {
		return Packet{}, false
	}

	var p Packet
	p.HasEpoch, p.Epoch = getFloat(layers, "frame.time_epoch")
	if v, ok := getString(layers, "ip.src"); ok {
		p.IPSrc = v
	}
	if v, ok := getString(layers, "ip.dst"); ok {
		p.IPDst = v
	}
	if v, ok := getUint(layers, "tcp.srcport"); ok {
		p.TCPsrc = v
	}
	if v, ok := getUint(layers, "tcp.dstport"); ok {
		p.TCPdst = v
	}
	if v, ok := getUint(layers, "udp.srcport"); ok {
		p.UDPsrc = v
	}
	if v, ok := getUint(layers, "udp.dstport"); ok {
		p.UDPdst = v
	}
	if v, ok := getString(layers, "dns.qry.name"); ok {
		p.DNSQuery = v
	}
	if v, ok := getUint(layers, "frame.len"); ok {
		p.FrameLen = v
	}
	return p, true
}

// Skippable reports whether an ek stream line is bookkeeping rather than data
// (the trailing {"index":...} summary lines TShark emits).
func Skippable(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || (strings.Contains(t, "\"index\"") && !strings.Contains(t, "\"_source\""))
}

func findLayers(raw map[string]any) map[string]any {
	if src, ok := raw["_source"].(map[string]any); ok {
		if l, ok := src["layers"].(map[string]any); ok {
			return l
		}
	}
	if l, ok := raw["layers"].(map[string]any); ok {
		return l
	}
	return nil
}

// first returns the first usable value for any of the given key spellings.
func first(layers map[string]any, names ...string) (any, bool) {
	for _, n := range names {
		v, ok := layers[n]
		if !ok {
			continue
		}
		switch tv := v.(type) {
		case string:
			if tv != "" {
				return tv, true
			}
		case []any:
			if len(tv) > 0 {
				if s, ok := tv[0].(string); ok && s != "" {
					return s, true
				}
			}
		case float64:
			return tv, true
		}
	}
	return nil, false
}

func getString(layers map[string]any, name string) (string, bool) {
	v, ok := first(layers, name, strings.ReplaceAll(name, ".", "_"))
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, s != ""
}

func getUint(layers map[string]any, name string) (uint32, bool) {
	v, ok := first(layers, name, strings.ReplaceAll(name, ".", "_"))
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return uint32(n), true
	case string:
		var out uint32
		for _, c := range n {
			if c < '0' || c > '9' {
				return 0, false
			}
			out = out*10 + uint32(c-'0')
		}
		return out, len(n) > 0
	}
	return 0, false
}

func getFloat(layers map[string]any, name string) (bool, float64) {
	v, ok := first(layers, name, strings.ReplaceAll(name, ".", "_"))
	if !ok {
		return false, 0
	}
	switch n := v.(type) {
	case float64:
		return true, n
	case string:
		var intPart, fracPart float64
		var seenDot bool
		var fracDiv float64 = 1
		neg := false
		i := 0
		if len(n) > 0 && (n[0] == '-' || n[0] == '+') {
			neg = n[0] == '-'
			i = 1
		}
		valid := i < len(n)
		for ; i < len(n); i++ {
			c := n[i]
			switch {
			case c == '.' && !seenDot:
				seenDot = true
			case c >= '0' && c <= '9':
				if seenDot {
					fracDiv *= 10
					fracPart = fracPart*10 + float64(c-'0')
				} else {
					intPart = intPart*10 + float64(c-'0')
				}
			default:
				return false, 0
			}
		}
		out := intPart + fracPart/fracDiv
		if neg {
			out = -out
		}
		return valid, out
	}
	return false, 0
}
