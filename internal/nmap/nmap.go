// Package nmap wraps the nmap CLI: argument construction, XML result parsing,
// and port-based OS guessing. Parsing is pure so it can be tested without
// executing nmap.
package nmap

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
)

// Stealth levels.
const (
	StealthFull    = 0
	StealthLight   = 1
	StealthPassive = 2
)

// TimingTemplate maps a stealth level to an nmap -T value.
func TimingTemplate(stealth uint8) string {
	switch stealth {
	case StealthFull:
		return "-T4"
	case StealthLight:
		return "-T2"
	default:
		return "-T1"
	}
}

// BackgroundScannerEnabled reports whether background scanning runs at this level.
func BackgroundScannerEnabled(stealth uint8) bool { return stealth < StealthPassive }

// BackgroundScannerInterval is seconds between background scans; 0 = disabled.
func BackgroundScannerInterval(stealth uint8) uint64 {
	switch stealth {
	case StealthFull:
		return 4
	case StealthLight:
		return 30
	default:
		return 0
	}
}

// Flags builds the nmap argv for a stealth level.
func Flags(stealth uint8, fast bool, target string) []string {
	var flags []string
	switch stealth {
	case StealthFull:
		if fast {
			flags = []string{"-sS", "--top-ports", "100", "--open", "-oX", "-", "-T4", "--min-rate", "1000"}
		} else {
			flags = []string{"-sV", "-O", "-sC", "--open", "-oX", "-", "-T4"}
		}
	case StealthLight:
		if fast {
			flags = []string{"-sn", "-T2", "--max-retries", "1", "--host-timeout", "10s"}
		} else {
			flags = []string{"-sn", "-T2", "--max-retries", "2", "--host-timeout", "15s"}
		}
	default:
		return nil // passive — no scanning
	}
	return append(flags, target)
}

// ── XML model (subset of nmaprun we care about) ─────────────────────────────

type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status    xmlStatus `xml:"status"`
	Addresses []xmlAddr `xml:"address"`
	Hostnames struct {
		Names []xmlHostname `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		PortList []xmlPort `xml:"port"`
	} `xml:"ports"`
	OS struct {
		Matches []xmlOSMatch `xml:"osmatch"`
	} `xml:"os"`
}

type xmlStatus struct {
	State string `xml:"state,attr"`
}

type xmlAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlPort struct {
	ID      uint32   `xml:"portid,attr"`
	Proto   string   `xml:"protocol,attr"`
	State   xmlState `xml:"state"`
	Service xmlSvc   `xml:"service"`
}

type xmlState struct {
	State string `xml:"state,attr"`
}

type xmlSvc struct {
	Name string `xml:"name,attr"`
}

type xmlOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// Device is a discovered host.
type Device struct {
	IP        string
	MAC       string
	MACVendor string
	Hostname  string
	OSGuess   string
	State     string
	Ports     []Port
}

// Port is an open (reported) service port.
type Port struct {
	ID      uint32
	Proto   string
	State   string
	Service string
}

// PortsString renders ports like "22/open/ssh, 443/open/https".
func (d Device) PortsString() string {
	parts := make([]string, len(d.Ports))
	for i, p := range d.Ports {
		svc := p.Service
		if svc == "" {
			svc = "?"
		}
		parts[i] = fmt.Sprintf("%d/%s/%s", p.ID, p.State, svc)
	}
	return strings.Join(parts, ", ")
}

// SummaryLine renders the human-readable device summary used in captures.
func (d Device) SummaryLine() string {
	host := d.Hostname
	if host == "" {
		host = "unknown"
	}
	osStr := d.OSGuess
	if osStr == "" {
		osStr = "OS unknown"
	}
	ports := d.PortsString()
	if ports == "" {
		ports = "no open ports"
	}
	return fmt.Sprintf("%s (%s) — %s [%s]", d.IP, host, osStr, ports)
}

// ParseXML extracts devices from nmap XML output.
func ParseXML(data []byte) []Device {
	var run xmlRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}
	var out []Device
	for _, h := range run.Hosts {
		dev := Device{State: h.Status.State}
		for _, a := range h.Addresses {
			switch a.AddrType {
			case "ipv4":
				dev.IP = a.Addr
			case "mac":
				dev.MAC = a.Addr
				dev.MACVendor = a.Vendor
			}
		}
		for _, hn := range h.Hostnames.Names {
			if hn.Name != "" && dev.Hostname == "" {
				dev.Hostname = hn.Name
			}
		}
		for _, p := range h.Ports.PortList {
			dev.Ports = append(dev.Ports, Port{
				ID:      p.ID,
				Proto:   p.Proto,
				State:   p.State.State,
				Service: p.Service.Name,
			})
		}
		for _, m := range h.OS.Matches {
			if m.Name != "" && dev.OSGuess == "" {
				dev.OSGuess = m.Name
			}
		}
		// Only report up hosts; when no status element exists assume up.
		if dev.IP != "" && (dev.State == "" || dev.State == "up") {
			out = append(out, dev)
		}
	}
	return out
}

// Summarize renders all device lines joined by newlines.
func Summarize(devices []Device) string {
	lines := make([]string, len(devices))
	for i, d := range devices {
		lines[i] = d.SummaryLine()
	}
	return strings.Join(lines, "\n")
}

// ExtractOpenPorts returns just the open port IDs from XML bytes.
func ExtractOpenPorts(data []byte) []uint32 {
	var ports []uint32
	for _, d := range ParseXML(data) {
		for _, p := range d.Ports {
			if p.State == "open" {
				ports = append(ports, p.ID)
			}
		}
	}
	return ports
}

// GuessOSFromPorts infers a platform hint from open port numbers.
// Order matters: more specific fingerprints come first.
func GuessOSFromPorts(ports []uint32) string {
	has := func(p uint32) bool {
		for _, x := range ports {
			if x == p {
				return true
			}
		}
		return false
	}
	switch {
	case has(9100) || has(631):
		return "printer/IoT"
	case has(554) || has(1935):
		return "camera/streaming"
	case has(22) && has(443) && has(80):
		return "Linux server"
	case has(3389) || has(5985) || has(5986):
		return "Windows"
	case has(445) && (has(135) || has(139)):
		return "Windows (SMB/RPC)"
	case has(88) && has(3268):
		return "Windows Domain Controller"
	case has(8443) && has(500):
		return "VPN/firewall appliance"
	case has(22) && has(443):
		return "Linux/Unix server"
	case has(22):
		return "Linux/Unix (SSH)"
	case has(443) || has(80):
		return "web server"
	default:
		return fmt.Sprintf("%d open port(s)", len(ports))
	}
}

// Runner executes nmap commands. Injectable for tests.
type Runner interface {
	Run(args ...string) (stdout []byte, err error)
}

// ExecRunner shells out to the real binary, wrapping with sudo when needed.
type ExecRunner struct{}

// SudoPrefixCmd returns a command that invokes prog via sudo unless already root.
func SudoPrefix(prog string) *exec.Cmd {
	isRoot := false
	if out, err := exec.Command("id", "-u").Output(); err == nil {
		isRoot = strings.TrimSpace(string(out)) == "0"
	}
	if isRoot {
		return exec.Command(prog)
	}
	return exec.Command("sudo", prog)
}

// Run implements Runner via os/exec.
func (ExecRunner) Run(args ...string) ([]byte, error) {
	cmd := SudoPrefix("nmap")
	cmd.Args = append(cmd.Args, args...)
	return cmd.Output()
}
