package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/hxmbl/hx_netkit/internal/config"
)

func newInitCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Interactive setup — write a correlator.toml",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if err := requireTerminal("init"); err != nil {
				return err
			}
			br := bufio.NewReader(cmd.InOrStdin())

			fmt.Fprintln(out, "═══ correlator init ═══")
			ifaces, err := listIfaces()
			if err != nil || len(ifaces) == 0 {
				return fmt.Errorf("no active network interfaces with addresses found; connect to a network and retry")
			}

			defIfaceIdx := 0
			options := make([]string, len(ifaces))
			for i, ifc := range ifaces {
				options[i] = ifc.describe()
				if ifc.Name == cfg.Interface {
					defIfaceIdx = i
				}
			}
			idx, ok := askChoice(br, out, "Interface", options, defIfaceIdx)
			if !ok {
				return fmt.Errorf("aborted")
			}
			chosen := ifaces[idx]

			target := suggestTarget(chosen)
			if target == "" {
				target = config.DefaultTarget
			}
			target, ok = askString(br, out, "Scan target CIDR", target)
			if !ok {
				return fmt.Errorf("aborted")
			}

			durStr, ok := askString(br, out, "Capture duration (seconds)",
				fmt.Sprint(cfg.Duration))
			if !ok {
				return fmt.Errorf("aborted")
			}
			duration := parseNonNeg(durStr, uint64(config.DefaultDuration))

			model, ok := askString(br, out, "Ollama model", config.ResolveModel("", cfg))
			if !ok {
				return fmt.Errorf("aborted")
			}

			stealth, ok := askChoice(br, out, "Stealth level",
				[]string{
					"0 · full scan (default) — aggressive nmap + background scanner",
					"1 · light — rate-limited nmap only",
					"2 · passive — TShark only, no scanning",
				}, int(0))
			if !ok {
				return fmt.Errorf("aborted")
			}

			webEnabled := false
			webEnabled, ok = askYesNo(br, out,
				"Allow the AI internet access? (websearch/webfetch)", false)
			if !ok {
				return fmt.Errorf("aborted")
			}

			tomlText := renderConfigToml(configTomlValues{
				Interface: chosen.Name,
				Target:    target,
				Duration:  duration,
				Model:     model,
				NumCtx:    cfg.NumCtx,
				Stealth:   stealth,
				WebEnable: webEnabled,
			})

			path := "./correlator.toml"
			if _, err := os.Stat(path); err == nil {
				overwrite, ok2 := askYesNo(br, out, "./correlator.toml exists — overwrite?", false)
				if !ok2 || !overwrite {
					path = filepath.Join(config.Dir(), "config.toml")
					os.MkdirAll(filepath.Dir(path), 0o755)
				}
			}
			if err := os.WriteFile(path, []byte(tomlText), 0o644); err != nil {
				return err
			}

			fmt.Fprintf(out, "\n✔ wrote %s\n", path)
			fmt.Fprintf(out, "  try: correlator run\n")
			return nil
		},
	}
}
