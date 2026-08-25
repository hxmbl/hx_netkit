package nmap

import (
	"strings"
	"testing"
)

const sampleXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host starttime="1">
  <status state="up" reason="arp-response"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Apple"/>
  <hostnames><hostname name="macbook.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    <port protocol="tcp" portid="9998"><state state="closed"/></port>
  </ports>
  <os><osmatch name="macOS 14" accuracy="98"/></os>
</host>
<host>
  <status state="down"/>
  <address addr="192.168.1.99" addrtype="ipv4"/>
</host>
</nmaprun>`

func TestParseXMLDevices(t *testing.T) {
	devices := ParseXML([]byte(sampleXML))
	if len(devices) != 1 {
		t.Fatalf("expected only the up host, got %d devices", len(devices))
	}
	d := devices[0]
	if d.IP != "192.168.1.10" || d.MAC != "AA:BB:CC:DD:EE:FF" || d.MACVendor != "Apple" {
		t.Errorf("address fields wrong: %+v", d)
	}
	if d.Hostname != "macbook.local" {
		t.Errorf("hostname = %q", d.Hostname)
	}
	if d.OSGuess != "macOS 14" {
		t.Errorf("os = %q", d.OSGuess)
	}
	open := 0
	for _, p := range d.Ports {
		if p.State == "open" {
			open++
		}
	}
	if open != 2 {
		t.Errorf("open ports = %d, want 2", open)
	}
}

func TestExtractOpenPortsOnlyOpen(t *testing.T) {
	got := ExtractOpenPorts([]byte(sampleXML))
	if len(got) != 2 || got[0] != 22 || got[1] != 443 {
		t.Errorf("open ports = %v, want [22 443]", got)
	}
	if got := ExtractOpenPorts([]byte("<nmaprun></nmaprun>")); len(got) != 0 {
		t.Errorf("empty xml should yield no ports")
	}
	if got := ExtractOpenPorts([]byte("garbage")); len(got) != 0 {
		t.Errorf("garbage should yield no ports, got %v", got)
	}
}

func TestPortsString(t *testing.T) {
	d := Device{Ports: []Port{
		{ID: 22, State: "open", Service: "ssh"},
		{ID: 80, State: "open"},
	}}
	want := "22/open/ssh, 80/open/?"
	if got := d.PortsString(); got != want {
		t.Errorf("ports string = %q, want %q", got, want)
	}
}

func TestSummaryLine(t *testing.T) {
	d := Device{IP: "10.0.0.1"}
	line := d.SummaryLine()
	if line != "10.0.0.1 (unknown) — OS unknown [no open ports]" {
		t.Errorf("summary = %q", line)
	}
}

func TestGuessOSFromPortsTable(t *testing.T) {
	cases := []struct {
		ports []uint32
		want  string
	}{
		{[]uint32{9100, 80}, "printer/IoT"},
		{[]uint32{631}, "printer/IoT"},
		{[]uint32{554, 80}, "camera/streaming"},
		{[]uint32{1935}, "camera/streaming"},
		{[]uint32{22, 80, 443}, "Linux server"},
		{[]uint32{3389, 445}, "Windows"},
		{[]uint32{5985}, "Windows"},
		{[]uint32{5986}, "Windows"},
		{[]uint32{445, 135}, "Windows (SMB/RPC)"},
		{[]uint32{445, 139}, "Windows (SMB/RPC)"},
		{[]uint32{88, 3268, 445}, "Windows Domain Controller"},
		{[]uint32{8443, 500}, "VPN/firewall appliance"},
		{[]uint32{22, 443}, "Linux/Unix server"},
		{[]uint32{22}, "Linux/Unix (SSH)"},
		{[]uint32{443}, "web server"},
		{[]uint32{80}, "web server"},
		{[]uint32{}, "0 open port(s)"},
		{[]uint32{9999, 8888}, "2 open port(s)"},
		// Priority ordering:
		{[]uint32{9100, 554, 1935}, "printer/IoT"},   // printer beats camera
		{[]uint32{9100, 22, 80, 443}, "printer/IoT"}, // printer beats linux server
		{[]uint32{8443}, "1 open port(s)"},           // 8443 alone ≠ web server
		{[]uint32{88}, "1 open port(s)"},             // 88 alone ≠ DC
	}
	for _, tc := range cases {
		if got := GuessOSFromPorts(tc.ports); got != tc.want {
			t.Errorf("GuessOS(%v) = %q, want %q", tc.ports, got, tc.want)
		}
	}
}

func TestFlagsPerStealthLevel(t *testing.T) {
	full := Flags(StealthFull, false, "192.168.1.0/24")
	joined := joinArgs(full)
	for _, want := range []string{"-sV", "-O", "-sC", "--open", "-oX", "-T4", "192.168.1.0/24"} {
		if !containsArg(joined, want) {
			t.Errorf("full flags missing %s: %v", want, full)
		}
	}
	fast := Flags(StealthFull, true, "t")
	if !containsArg(joinArgs(fast), "--min-rate") {
		t.Errorf("fast mode missing --min-rate: %v", fast)
	}
	light := Flags(StealthLight, false, "t")
	if !containsArg(joinArgs(light), "-sn") || !containsArg(joinArgs(light), "-T2") {
		t.Errorf("light flags wrong: %v", light)
	}
	if passive := Flags(StealthPassive, false, "t"); passive != nil {
		t.Errorf("passive must produce no scan args, got %v", passive)
	}
}

func TestTimingAndScannerIntervals(t *testing.T) {
	if TimingTemplate(StealthFull) != "-T4" || TimingTemplate(StealthLight) != "-T2" ||
		TimingTemplate(StealthPassive) != "-T1" {
		t.Error("timing templates wrong")
	}
	if BackgroundScannerEnabled(StealthPassive) {
		t.Error("passive must disable background scanner")
	}
	if BackgroundScannerInterval(StealthFull) != 4 || BackgroundScannerInterval(StealthLight) != 30 {
		t.Error("intervals wrong")
	}
}

func joinArgs(a []string) string {
	out := ""
	for _, s := range a {
		out += "\x00" + s + "\x00"
	}
	return out
}

func containsArg(joined, arg string) bool { return strings.Contains(joined, "\x00"+arg+"\x00") }
