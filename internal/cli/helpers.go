package cli

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/hxmbl/hx_netkit/internal/config"
)

var styleDimText = lipgloss.NewStyle().Faint(true).Render

func captureSeqOf(name string) int64 { return config.CaptureSeq(name) }

func captureNameLess(a, b string) bool { return config.CaptureNameLess(a, b) }

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(s), 64)
}
