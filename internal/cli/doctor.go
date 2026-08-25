package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hxmbl/hx_netkit/internal/config"
	"github.com/hxmbl/hx_netkit/internal/llm"
	"github.com/hxmbl/hx_netkit/internal/ui"
)

type check struct {
	name   string
	status ui.Status
	detail string
	hints  []string
}

func newDoctorCmd(cfg config.Config) *cobra.Command {
	var colorOverride string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Verify the environment: tools, interfaces, Ollama, data dir",
		Long: "Checks everything correlator needs to run and prints actionable\n" +
			"remediation hints for anything that fails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			color := false
			if f, ok := out.(*os.File); ok && isTerminal(f) {
				color = true
			}
			switch strings.ToLower(colorOverride) {
			case "always":
				color = true
			case "never":
				color = false
			}

			checks := runDoctorChecks(cfg)
			fails := 0
			for _, c := range checks {
				fmt.Fprintf(out, "%s %-12s %s\n", ui.Status(c.status).String(color), pad(c.name, 12), c.detail)
				for _, h := range c.hints {
					fmt.Fprintf(out, "      → %s\n", h)
				}
				if c.status == ui.StatusFail {
					fails++
				}
			}
			fmt.Fprintf(out,
				"\n%d check(s) failed · run `correlator init` to fix configuration\n", fails)
			if fails > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&colorOverride, "color", "", "force color: always|never")
	return cmd
}

func pad(s string, w int) string {
	for len(s) < w {
		s += " "
	}
	return s
}

// binaryCheck verifies presence + version of an external tool.
func binaryCheck(name string) check {
	path, err := lookPath(name)
	if err != nil {
		return check{name: name, status: ui.StatusFail,
			detail: "not found in PATH",
			hints: []string{
				fmt.Sprintf("macOS: brew install %s", installName(name)),
				fmt.Sprintf("Debian/Ubuntu: sudo apt install %s", installName(name)),
			}}
	}
	version := probeVersion(name)
	detail := version
	if detail == "" {
		detail = path
	} else {
		detail = fmt.Sprintf("%s (%s)", version, path)
	}
	return check{name: name, status: ui.StatusOK, detail: detail}
}

func installName(tool string) string {
	if tool == "tshark" {
		return "wireshark"
	}
	return tool
}

// ollamaCheck verifies the daemon is reachable and the configured model exists.
func ollamaCheck(cfg config.Config) check {
	model := config.ResolveModel("", cfg)
	client := llm.New(cfg.OllamaURL, model, cfg.NumCtx)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !client.Available(ctx) {
		local := strings.Contains(cfg.OllamaURL, "localhost") || strings.Contains(cfg.OllamaURL, "127.0.0.1")
		c := check{name: "ollama", status: ui.StatusFail,
			detail: fmt.Sprintf("not reachable at %s", cfg.OllamaURL)}
		if local {
			c.hints = append(c.hints,
				"macOS: brew install ollama && brew services start ollama",
				"Linux: curl -fsSL https://ollama.com/install.sh | sh")
		}
		c.hints = append(c.hints, "or point ollama_url in correlator.toml at your daemon")
		return c
	}

	pulled, err := listOllamaModels(cfg.OllamaURL)
	if err != nil {
		return check{name: "ollama", status: ui.StatusWarn,
			detail: "reachable but model list unavailable"}
	}
	for _, m := range pulled {
		if m == model || m == model+":latest" {
			return check{name: "ollama", status: ui.StatusOK,
				detail: fmt.Sprintf("%s · model %q ready", cfg.OllamaURL, model)}
		}
	}
	return check{name: "ollama", status: ui.StatusWarn,
		detail: fmt.Sprintf("reachable, but model %q is not pulled", model),
		hints:  []string{"ollama pull " + model}}
}

func listOllamaModels(baseURL string) ([]string, error) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/api/tags", nil)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var parsed struct {
		Models []struct{ Name string } `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(parsed.Models))
	for _, m := range parsed.Models {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out, nil
}

// interfaceCheck lists capture-capable interfaces and warns when the
// configured one doesn't exist.
func interfaceCheck(cfg config.Config) check {
	ifaces, err := listIfaces()
	if err != nil || len(ifaces) == 0 {
		return check{name: "interfaces", status: ui.StatusWarn,
			detail: "none found with addresses (VPN-only setup?)",
			hints:  []string{"capture needs an active interface; connect to a network first"}}
	}
	descriptions := make([]string, len(ifaces))
	found := false
	for i, ifc := range ifaces {
		descriptions[i] = ifc.describe()
		if ifc.Name == cfg.Interface {
			found = true
		}
	}
	c := check{name: "interfaces", status: ui.StatusOK, detail: strings.Join(descriptions, ", ")}
	if !found && cfg.Interface != "" {
		c.status = ui.StatusWarn
		c.detail = fmt.Sprintf("configured interface %q not present; candidates: %s",
			cfg.Interface, strings.Join(descriptions, ", "))
		c.hints = []string{"correlator init   # pick the right interface interactively"}
	}
	return c
}

// diskCheck reports free space in the captures directory.
func diskCheck() check {
	dir := config.CapturesDir()
	free, err := freeBytes(dir)
	if err != nil {
		return check{name: "data dir", status: ui.StatusOK, detail: dir}
	}
	const gb = 1024 * 1024 * 1024
	switch {
	case free > 5*gb:
		return check{name: "data dir", status: ui.StatusOK,
			detail: fmt.Sprintf("%s (%.1f GB free)", dir, float64(free)/gb)}
	case free > gb:
		return check{name: "data dir", status: ui.StatusWarn,
			detail: fmt.Sprintf("%s (%.1f GB free)", dir, float64(free)/gb),
			hints:  []string{"captures grow quickly; consider `correlator captures prune`"}}
	default:
		return check{name: "data dir", status: ui.StatusFail,
			detail: fmt.Sprintf("%s (%.2f GB free)", dir, float64(free)/gb),
			hints:  []string{"free up space or point captures elsewhere"}}
	}
}

func rootCheck() check {
	if os.Geteuid() == 0 {
		return check{name: "privileges", status: ui.StatusOK,
			detail: "running as root — tshark/nmap need no sudo wrapper"}
	}
	return check{name: "privileges", status: ui.StatusWarn,
		detail: "not root — captures will prompt via sudo",
		hints:  []string{"optional: run captures once with sudo, or grant dumpcap capabilities"}}
}

func configCheck(cfg config.Config) check {
	if cfg.Loaded() {
		return check{name: "config", status: ui.StatusOK, detail: "loaded"}
	}
	return check{name: "config", status: ui.StatusOK,
		detail: "no file found — using defaults (correlator init writes one)"}
}

func runDoctorChecks(cfg config.Config) []check {
	checks := []check{
		binaryCheck("tshark"),
		binaryCheck("nmap"),
		interfaceCheck(cfg),
		ollamaCheck(cfg),
		configCheck(cfg),
		diskCheck(),
	}
	if runtime.GOOS != "windows" {
		checks = append(checks, rootCheck())
	}
	return checks
}

// ── platform helpers ────────────────────────────────────────────────────────

func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// probeVersion returns the first line of `<tool> --version`, if available.
func probeVersion(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, "--version").Output()
	if err != nil {
		return ""
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return first
}

// freeBytes reports available bytes on the filesystem containing path.
func freeBytes(path string) (uint64, error) {
	os.MkdirAll(path, 0o755)
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
