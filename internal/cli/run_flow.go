package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hxmbl/hx_netkit/internal/capture"
	"github.com/hxmbl/hx_netkit/internal/config"
	netctx "github.com/hxmbl/hx_netkit/internal/context"
	"github.com/hxmbl/hx_netkit/internal/llm"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/ui"
)

func newRunCmd(cfg config.Config) *cobra.Command {
	var allowWeb, yes bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Guided flow — doctor → capture → analyze → chat",
		Long: "Interactive one-command pipeline: verifies the environment,\n" +
			"picks an interface, captures traffic, analyzes it, and offers to\n" +
			"drop into the AI chat with findings loaded.",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			color := false
			if f, ok := out.(*os.File); ok {
				color = isTerminal(f)
			}
			if err := requireTerminal("run"); err != nil {
				return err
			}
			br := bufio.NewReader(cmd.InOrStdin())

			// 1 ─ environment gate
			fmt.Fprintln(out, "═══ correlator run ═══")
			for _, name := range []string{"tshark", "nmap"} {
				c := binaryCheck(name)
				if c.status == ui.StatusFail {
					fmt.Fprintf(out, "%s %-8s %s\n", ui.StatusFail.String(color), name, "missing")
					for _, h := range c.hints {
						fmt.Fprintf(out, "    → %s\n", h)
					}
					return fmt.Errorf("install the missing tool and re-run `correlator run`")
				}
				fmt.Fprintf(out, "%s %-8s %s\n", ui.StatusOK.String(color), name, c.detail)
			}

			// 2 ─ interface + target + duration + stealth
			ifaces, err := listIfaces()
			if err != nil || len(ifaces) == 0 {
				return fmt.Errorf("no active interfaces found; connect to a network first")
			}
			defIdx := 0
			opts := make([]string, len(ifaces))
			for i, ifc := range ifaces {
				opts[i] = ifc.describe()
				if ifc.Name == cfg.Interface {
					defIdx = i
				}
			}
			idx, ok := askChoice(br, out, "Interface", opts, defIdx)
			if !ok {
				return fmt.Errorf("aborted")
			}
			chosen := ifaces[idx]

			target := suggestTarget(chosen)
			if target == "" {
				target = cfg.Target
			}
			target, ok = askString(br, out, "Target CIDR", target)
			if !ok {
				return fmt.Errorf("aborted")
			}
			durStr, ok := askString(br, out, "Capture duration (seconds)", fmt.Sprint(cfg.Duration))
			if !ok {
				return fmt.Errorf("aborted")
			}
			duration := parseNonNeg(durStr, uint64(cfg.Duration))

			stealthIdx, ok2 := askChoice(br, out, "Stealth level",
				[]string{"0 · full scan", "1 · light scan", "2 · passive"}, 0)
			if !ok2 {
				return fmt.Errorf("aborted")
			}

			start, ok3 := askYesNo(br, out,
				fmt.Sprintf("Capture on %s for %ds. Start?", chosen.Name, duration), true)
			if !ok3 || !start {
				return fmt.Errorf("aborted")
			}

			// 3 ─ capture
			dbPath := store.CapturePath(false, "")
			if _, _, err := capture.Run(capture.Options{
				Interface:    chosen.Name,
				Target:       target,
				DurationSecs: duration,
				StealthLevel: uint8(stealthIdx),
				DBPath:       dbPath,
				Color:        color,
			}); err != nil {
				return err
			}

			// 4 ─ analyze
			db, err := store.OpenExisting(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			netCtx, err := netctx.Build(db, cfg.CorporateMode)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "\n═══ FINDINGS (%d IPs analyzed) ═══\n", len(netCtx.Profiles))
			ui.RenderFindings(out, netCtx.Findings, ui.FindingsOptions{
				Color:      color,
				KindFilter: "all",
				TopN:       15,
			})

			// 5 ─ offer chat
			client := llm.New(cfg.OllamaURL, config.ResolveModel("", cfg), cfg.NumCtx)
			if !client.Available(context.Background()) {
				fmt.Fprintf(out, "[Hint] Ollama not reachable — skipping chat. Fix: %s\n",
					ollamaInstallHint(cfg))
				return nil
			}
			wantChat, okChat := askYesNo(br, out, "Open AI chat about this capture?", true)
			if !okChat || !wantChat {
				return nil
			}
			webCfg := cfg.Web
			if allowWeb {
				webCfg.Enabled = true
			}
			return runChat(chatOptions{
				DBPath:  dbPath,
				Model:   config.ResolveModel("", cfg),
				Stealth: 2,
				Cfg:     cfg,
				Web:     webCfg,
				AutoYes: yes,
			})
		},
	}
	cmd.Flags().BoolVar(&allowWeb, "allow-web", false, "permit AI websearch/webfetch tools this session")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "auto-approve AI tool calls")
	return cmd
}

func ollamaInstallHint(cfg config.Config) string {
	model := config.ResolveModel("", cfg)
	return fmt.Sprintf("`ollama serve` then `ollama pull %s`, or fix ollama_url in config", model)
}
