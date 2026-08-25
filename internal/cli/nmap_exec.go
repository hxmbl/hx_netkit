package cli

import (
	"github.com/hxmbl/hx_netkit/internal/nmap"
)

// nmapExecRunner adapts nmap.ExecRunner for CLI commands.
type nmapExecRunner struct{}

func (nmapExecRunner) Run(args ...string) ([]byte, error) {
	return nmap.ExecRunner{}.Run(args...)
}

func parseNmap(xml []byte) []nmap.Device         { return nmap.ParseXML(xml) }
func summarizeNmap(devices []nmap.Device) string { return nmap.Summarize(devices) }
