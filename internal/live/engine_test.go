package live

import (
	"strconv"
	"strings"
	"testing"
)

func u16(v uint16) *uint16 { return &v }

func TestProcessPacketTracksRoles(t *testing.T) {
	e := NewEngine()
	e.ProcessPacket(1000, "10.0.0.1", "10.0.0.2", nil, "")
	e.ProcessPacket(1001, "10.0.0.1", "10.0.0.2", u16(443), "")
	e.ProcessPacket(1002, "10.0.0.3", "8.8.8.8", nil, "netflix.com")

	if len(e.roles) != 4 {
		t.Fatalf("roles = %d, want 4", len(e.roles))
	}
	src := e.roles["10.0.0.1"]
	if src.packetCount != 2 || !containsPort(src.ports, 443) {
		t.Errorf("src role wrong: %+v", src)
	}
	dst := e.roles["10.0.0.2"]
	if dst.detail != "serves HTTPS (443)" || dst.confidence != 0.7 {
		t.Errorf("dst role detail = %q conf=%f", dst.detail, dst.confidence)
	}
	if q := e.roles["8.8.8.8"]; q.detail != "queries netflix.com" || q.confidence != 0.6 {
		t.Errorf("dns dst role wrong: %+v", q)
	}
}

func TestMulticastIgnored(t *testing.T) {
	e := NewEngine()
	e.ProcessPacket(1000, "224.0.0.251", "10.0.0.5", nil, "")
	e.ProcessPacket(1001, "10.0.0.6", "239.255.255.250", nil, "")
	e.ProcessPacket(1002, "10.0.0.7", "255.255.255.255", nil, "")
	if len(e.roles) != 0 {
		t.Errorf("multicast leaked into engine: %+v", e.roles)
	}
}

func TestInterpretClassification(t *testing.T) {
	cases := []struct {
		name  string
		ports []uint16
		pkts  int
		dns   []string
		want  string
	}{
		{"web server", []uint16{80, 443, 22}, 10, nil, "server (HTTP + SSH)"},
		{"plain web", []uint16{80}, 3, nil, "device on web"},
		{"chromecast", []uint16{8009}, 3, nil, "Chromecast"},
		{"mdns", []uint16{5353}, 3, nil, "mDNS device"},
		{"upnp", []uint16{5000}, 3, nil, "UPnP/DLNA"},
		{"printer", []uint16{9100}, 3, nil, "printer"},
		{"ssh host", []uint16{22}, 3, nil, "Linux/Mac device"},
		{"browser", nil, 3, []string{"a.com", "b.com", "c.com", "d.com"}, "active browser"},
		{"busy", nil, 200, nil, "high-traffic device"},
		{"quiet", nil, 5, nil, "IoT/embedded"},
	}
	for _, tc := range cases {
		e := NewEngine()
		for i := 0; i < maxInt(tc.pkts, len(tc.ports)); i++ {
			var p *uint16
			if len(tc.ports) > 0 {
				pp := tc.ports[i%len(tc.ports)]
				p = &pp
			}
			e.ProcessPacket(float64(1000+i), "10.0.0."+tc.name[:1]+"9", "10.0.1.2", p, "")
		}
		for _, d := range tc.dns {
			e.ProcessPacket(1100, "10.0.0."+tc.name[:1]+"9", "10.0.1.3", nil, d)
		}
		inters := e.Interpret()
		found := false
		for _, it := range inters {
			if strings.Contains(it.Desc, tc.want) && strings.HasPrefix(it.Desc, "[10.0.0.") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: expected classification %q in %v", tc.name, tc.want, inters)
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func TestInterpretTop20AndDNSList(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 30; i++ {
		ip := "10." + itoa(i/256) + "." + itoa(i%256) + ".1"
		for j := 0; j <= i; j++ { // escalating packet counts
			e.ProcessPacket(float64(1000+j), ip, "10.99.0.1", nil, "")
		}
	}
	inters := e.Interpret()
	if len(inters) != 20 {
		t.Fatalf("interpretations = %d, want capped at 20", len(inters))
	}
	first := inters[0]
	if !strings.Contains(first.Desc, "pkts") {
		t.Errorf("missing pkt count: %q", first.Desc)
	}
}

func TestServiceName(t *testing.T) {
	if ServiceName(443) != "HTTPS" || ServiceName(9100) != "Printer" || ServiceName(1) != "?" {
		t.Error("service name table broken")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
