// Package cli wires the correlator subcommands.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/hxmbl/hx_netkit/internal/capture"
	"github.com/hxmbl/hx_netkit/internal/config"
	ctxpkg "github.com/hxmbl/hx_netkit/internal/context"
	"github.com/hxmbl/hx_netkit/internal/intel"
	"github.com/hxmbl/hx_netkit/internal/llm"
	"github.com/hxmbl/hx_netkit/internal/nlsearch"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/textutil"
	"github.com/hxmbl/hx_netkit/internal/tools"
	"github.com/hxmbl/hx_netkit/internal/version"
)

// NewRootCmd assembles the full command tree.
func NewRootCmd() *cobra.Command {
	cfg := config.Load()

	root := &cobra.Command{
		Use:   "correlator",
		Short: "Network intelligence — scan, capture, interpret, chat",
		Long: "correlator scans, captures and interrogates your network.\n" +
			"No cloud. No telemetry. AI runs locally via Ollama; internet access for the\n" +
			"AI is opt-in via [web] config or --allow-web.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newCaptureCmd(cfg),
		newLiveInterpretCmd(cfg),
		newChatCmd(cfg),
		newAnalyzeCmd(),
		newAskCmd(cfg),
		newReportCmd(cfg),
		newScanCmd(cfg),
		newSearchCmd(),
		newQueryCmd(),
		newStatsCmd(),
		newDNSCmd(),
		newTopTalkersCmd(),
		newDevicesCmd(),
		newListCmd(),
		newVersionCmd(),
	)
	return root
}

func addDBFlag(c *cobra.Command, p *string) {
	c.Flags().StringVarP(p, "db", "d", "", "capture database path (default: latest capture)")
}

func mustDB(path string) *store.DB {
	if path == "" {
		p, err := config.LatestDB()
		if err != nil {
			fmt.Fprintln(os.Stderr, "[Error] No database specified and no captures found. Run: correlator capture")
			os.Exit(1)
		}
		path = p
	}
	db, err := store.OpenExisting(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Error] %v\n", err)
		os.Exit(1)
	}
	return db
}

// ── capture ─────────────────────────────────────────────────────────────────

func newCaptureCmd(cfg config.Config) *cobra.Command {
	var iface, target, output string
	var duration uint64
	var noSave, fast, noNmap, noTShark, debug bool
	var stealth int

	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture packets + nmap scan in parallel, store metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := capture.Options{
				Interface:    firstNonEmpty(iface, cfg.Interface),
				Target:       firstNonEmpty(target, cfg.Target),
				DurationSecs: duration,
				Fast:         fast,
				NoNmap:       noNmap,
				NoTShark:     noTShark,
				Debug:        debug,
				StealthLevel: uint8(stealth),
				DBPath:       store.CapturePath(noSave, output),
			}
			if duration == 0 {
				opts.DurationSecs = cfg.Duration
			}
			_, _, err := capture.Run(opts)
			return err
		},
	}
	cmd.Flags().StringVarP(&iface, "interface", "i", "", "network interface")
	cmd.Flags().StringVarP(&target, "target", "t", "", "CIDR target for nmap")
	cmd.Flags().Uint64VarP(&duration, "duration", "D", 0, "capture duration in seconds")
	cmd.Flags().BoolVar(&noSave, "no-save", false, "don't persist the capture")
	cmd.Flags().StringVarP(&output, "output", "o", "", "database output path")
	cmd.Flags().BoolVar(&fast, "fast", false, "fast nmap mode")
	cmd.Flags().BoolVar(&noNmap, "no-nmap", false, "skip nmap scanning")
	cmd.Flags().BoolVar(&noTShark, "no-tshark", false, "skip packet capture")
	cmd.Flags().BoolVar(&debug, "debug", false, "print raw tshark lines")
	cmd.Flags().IntVar(&stealth, "stealth-level", 0, "0=full scan, 1=light, 2=passive (no scanning)")
	return cmd
}

// ── live-interpret ──────────────────────────────────────────────────────────

func newLiveInterpretCmd(cfg config.Config) *cobra.Command {
	var iface, output, model string
	var duration uint64
	var noSave, verbose, useAI bool

	cmd := &cobra.Command{
		Use:   "live-interpret",
		Short: "Real-time packet interpretation — no AI needed",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved := config.ResolveModel(model, cfg)
			return runLiveInterpret(liveOptions{
				Interface:    firstNonEmpty(iface, cfg.Interface),
				DurationSecs: duration,
				NoSave:       noSave,
				Output:       output,
				Verbose:      verbose,
				UseAI:        useAI,
				Model:        resolved,
				Cfg:          cfg,
			})
		},
	}
	cmd.Flags().StringVarP(&iface, "interface", "i", "", "network interface")
	cmd.Flags().Uint64VarP(&duration, "duration", "D", 0, "capture duration in seconds")
	cmd.Flags().BoolVar(&noSave, "no-save", false, "don't persist")
	cmd.Flags().StringVarP(&output, "output", "o", "", "database output path")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose per-packet output")
	cmd.Flags().BoolVar(&useAI, "ai", false, "drop into AI chat after capture starts")
	cmd.Flags().StringVar(&model, "model", "", "Ollama model override")
	return cmd
}

// ── chat ────────────────────────────────────────────────────────────────────

func newChatCmd(cfg config.Config) *cobra.Command {
	var dbPath, model string
	var stealth int
	var allowWeb, yes bool

	cmd := &cobra.Command{
		Use:   "chat",
		Short: "Chat with local AI about captured network data",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbPath == "" {
				p, err := config.LatestDB()
				if err != nil {
					return fmt.Errorf("no captures found. Run: correlator capture")
				}
				dbPath = p
			}
			if !cfg.AI.Enabled {
				fmt.Println("[System] AI disabled in config. Entering search mode.")
				runSearchREPL(dbPath, "")
				return nil
			}
			webCfg := cfg.Web
			if allowWeb {
				webCfg.Enabled = true
			}
			return runChat(chatOptions{
				DBPath:  dbPath,
				Model:   config.ResolveModel(model, cfg),
				Stealth: uint8(stealth),
				Cfg:     cfg,
				Web:     webCfg,
				AutoYes: yes,
			})
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().StringVar(&model, "model", "", "Ollama model override")
	cmd.Flags().IntVar(&stealth, "stealth-level", 0, "0=full, 1=light, 2=passive")
	cmd.Flags().BoolVar(&allowWeb, "allow-web", false, "permit AI websearch/webfetch tools this session")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "auto-approve tool calls without prompting")
	return cmd
}

// ── analyze (offline findings) ──────────────────────────────────────────────

func newAnalyzeCmd() *cobra.Command {
	var dbPath string
	var corporate bool
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Run behavioral detectors on a capture — no AI required",
		RunE: func(cmd *cobra.Command, args []string) error {
			db := mustDB(dbPath)
			defer db.Close()
			c, err := ctxpkg.Build(db, corporate)
			if err != nil {
				return err
			}
			fmt.Printf("═══ FINDINGS (%d packets, %d IPs) ═══\n", c.PacketCount, len(c.Profiles))
			fmt.Print(intel.FormatFindings(c.Findings))
			if len(c.Summaries) > 0 {
				fmt.Println("\n═══ DEVICE NARRATIVES ═══")
				for _, s := range c.Summaries {
					fmt.Println(s.String())
				}
			}
			if c.CrossRef != "" {
				fmt.Println("\n═══ CROSS REFERENCE ═══")
				fmt.Println(c.CrossRef)
			}
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().BoolVar(&corporate, "corporate", false, "hide consumer detectors (game/streaming/cloud)")
	return cmd
}

// ── ask ─────────────────────────────────────────────────────────────────────

func newAskCmd(cfg config.Config) *cobra.Command {
	var dbPath, model, question string
	cmd := &cobra.Command{
		Use:   "ask",
		Short: "Ask the local AI a single question about a capture",
		RunE: func(cmd *cobra.Command, args []string) error {
			if question == "" {
				return fmt.Errorf("a question is required (-q)")
			}
			db := mustDB(dbPath)
			defer db.Close()
			c, err := ctxpkg.Build(db, cfg.CorporateMode)
			if err != nil {
				return err
			}
			client := llm.New(cfg.OllamaURL, config.ResolveModel(model, cfg), cfg.NumCtx)
			if !client.Available(context.Background()) {
				return fmt.Errorf("Ollama not available at %s", cfg.OllamaURL)
			}
			prompt := c.FormatForAI() + "\n\n## Question\n" + question
			answer, err := client.Generate(context.Background(), prompt)
			if err != nil {
				return err
			}
			fmt.Println(answer)
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().StringVarP(&question, "question", "q", "", "the question to answer")
	cmd.Flags().StringVar(&model, "model", "", "Ollama model override")
	return cmd
}

// ── report ──────────────────────────────────────────────────────────────────

func newReportCmd(cfg config.Config) *cobra.Command {
	var dbPath, model string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate an AI network security report from a capture",
		RunE: func(cmd *cobra.Command, args []string) error {
			db := mustDB(dbPath)
			defer db.Close()
			c, err := ctxpkg.Build(db, cfg.CorporateMode)
			if err != nil {
				return err
			}
			client := llm.New(cfg.OllamaURL, config.ResolveModel(model, cfg), cfg.NumCtx)
			if !client.Available(context.Background()) {
				return fmt.Errorf("Ollama not available at %s", cfg.OllamaURL)
			}
			findingsJSON, _ := json.MarshalIndent(c.Findings, "", "  ")
			devLines := make([]string, len(c.Devices))
			for i, d := range c.Devices {
				host := d.Hostname
				if host == "" {
					host = "?"
				}
				devLines[i] = fmt.Sprintf("%s (%s) [%s]", d.IP, host, d.Ports)
			}
			nmapStr := strings.Join(c.NmapSummaries, "\n")
			if nmapStr == "" {
				nmapStr = "(no nmap scan data)"
			}
			prompt := fmt.Sprintf(`Generate a comprehensive network security report based on this data:

%s

Devices:
%s

Findings:
%s`, c.FormatForAI(), strings.Join(devLines, "\n"), findingsJSON)
			answer, err := client.Generate(context.Background(), prompt)
			if err != nil {
				return err
			}
			fmt.Println(answer)
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().StringVar(&model, "model", "", "Ollama model override")
	return cmd
}

// ── scan ────────────────────────────────────────────────────────────────────

func newScanCmd(cfg config.Config) *cobra.Command {
	var target, output string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run nmap only and save results",
		RunE: func(cmd *cobra.Command, args []string) error {
			tgt := target
			if tgt == "" {
				fmt.Print("Target CIDR (e.g. 192.168.1.0/24): ")
				reader := bufio.NewReader(os.Stdin)
				line, _ := reader.ReadString('\n')
				tgt = strings.TrimSpace(line)
			}
			if tgt == "" {
				return fmt.Errorf("no target given")
			}
			dbPath := store.CapturePath(false, output)
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			runner := nmapExecRunner{}
			xmlOut, err := runner.Run("-sV", "-O", "-sC", "--open", "-oX", "-", "-T4", tgt)
			if err != nil {
				return fmt.Errorf("failed to run nmap: %w. Is it installed?", err)
			}
			now := float64(timeNowUnixNano()) / 1e9
			devices := parseNmap(xmlOut)
			for _, d := range devices {
				_ = db.UpsertDevice(d.IP, d.MAC, d.Hostname, d.MACVendor, d.OSGuess, d.PortsString(), now)
			}
			summary := summarizeNmap(devices)
			_ = db.RecordScan(tgt, string(xmlOut), summary, now)
			fmt.Println(summary)
			fmt.Printf("[System] Saved to %s\n", dbPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&target, "target", "t", "", "CIDR or IP to scan")
	cmd.Flags().StringVarP(&output, "output", "o", "", "database output path")
	return cmd
}

// ── search ──────────────────────────────────────────────────────────────────

func newSearchCmd() *cobra.Command {
	var dbPath, query string
	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search network data — no AI, just smart queries",
		RunE: func(cmd *cobra.Command, args []string) error {
			runSearchREPL(dbPath, query)
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().StringVarP(&query, "query", "q", "", "run one query and exit")
	return cmd
}

func runSearchREPL(dbPath, initial string) {
	db := mustDB(dbPath)
	defer db.Close()

	if initial != "" {
		fmt.Println(nlsearch.Execute(db, initial))
		return
	}

	fmt.Println("\n═══════ NETWORK SEARCH ENGINE ═══════")
	fmt.Printf("[System] Database: %s\n", dbPath)
	fmt.Println("[System] Commands: ip <addr>, port <num>, dns <domain>, find <text>, devices, stats, help, quit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("search> ")
		if !scanner.Scan() {
			break
		}
		q := strings.TrimSpace(scanner.Text())
		if q == "" {
			continue
		}
		if q == "quit" || q == "exit" || q == "q" {
			break
		}
		out := nlsearch.Execute(db, q)
		if out != "" {
			fmt.Println(out)
		}
	}
	fmt.Println("\n[System] Search ended.")
}

// ── query ───────────────────────────────────────────────────────────────────

func newQueryCmd() *cobra.Command {
	var dbPath, format string
	cmd := &cobra.Command{
		Use:   "query <sql>",
		Short: "Query captured packets with SQL (read-only)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sqlText := strings.Join(args, " ")
			if err := tools.SafeSQL(sqlText); err != nil {
				return fmt.Errorf("[Error] Rejected: %v", err)
			}
			db := mustDB(dbPath)
			defer db.Close()
			cols, rows, err := db.QueryRows(sqlText, 10000)
			if err != nil {
				return fmt.Errorf("[Error] Query failed: %v", err)
			}
			w := bufio.NewWriter(os.Stdout)
			defer w.Flush()
			if format == "csv" {
				fmt.Fprintln(w, strings.Join(cols, ","))
				for _, r := range rows {
					fmt.Fprintln(w, strings.Join(r, ","))
				}
			} else {
				fmt.Fprintln(w, cols)
				fmt.Fprintln(w, strings.Repeat("-", 60))
				for _, r := range rows {
					fmt.Fprintln(w, r)
				}
			}
			fmt.Fprintf(w, "\n%d rows\n", len(rows))
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|csv")
	return cmd
}

// ── stats / dns / top-talkers / devices ─────────────────────────────────────

func newStatsCmd() *cobra.Command {
	var dbPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show traffic stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			db := mustDB(dbPath)
			defer db.Close()
			s, err := db.Stats()
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(s)
			}
			fmt.Println("═══ DATABASE STATS ═══")
			fmt.Printf("  Packets: %d\n", s.Packets)
			fmt.Printf("  Devices: %d\n", s.Devices)
			fmt.Printf("  DNS domains: %d\n", s.DNSDomains)
			fmt.Printf("  Nmap scans: %d\n", s.NmapScans)
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func newDNSCmd() *cobra.Command {
	var dbPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "List DNS queries",
		RunE: func(cmd *cobra.Command, args []string) error {
			db := mustDB(dbPath)
			defer db.Close()
			rows, err := db.DNSQueries()
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			fmt.Println("═══ DNS QUERIES ═══")
			for _, r := range rows {
				fmt.Printf("  %s → %s (×%d)\n", r.Src, r.Query, r.Count)
			}
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func newTopTalkersCmd() *cobra.Command {
	var dbPath string
	var limit int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "top-talkers",
		Short: "List top talkers",
		RunE: func(cmd *cobra.Command, args []string) error {
			db := mustDB(dbPath)
			defer db.Close()
			rows, err := db.TopTalkers(limit)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			fmt.Println("═══ TOP TALKERS ═══")
			for _, r := range rows {
				fmt.Printf("  %s: %d packets\n", r.IP, r.Count)
			}
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().IntVarP(&limit, "limit", "l", 20, "how many talkers")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func newDevicesCmd() *cobra.Command {
	var dbPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "List known devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			db := mustDB(dbPath)
			defer db.Close()
			rows, err := db.Devices()
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			fmt.Println("═══ KNOWN DEVICES ═══")
			for _, r := range rows {
				host, osG := "", ""
				if r.Hostname != nil {
					host = *r.Hostname
				}
				if r.OSGuess != nil {
					osG = *r.OSGuess
				}
				ports := r.Ports
				if ports == "" {
					ports = "no ports"
				}
				fmt.Printf("  %s (%s) — %s [%s]\n", r.IP, host, osG, ports)
			}
			return nil
		},
	}
	addDBFlag(cmd, &dbPath)
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

// ── list ────────────────────────────────────────────────────────────────────

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List saved capture databases",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := config.CapturesDir()
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				fmt.Printf("[System] No captures yet (%s doesn't exist)\n", dir)
				return nil
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			type sized struct {
				name string
				size int64
			}
			var dbs []sized
			for _, e := range entries {
				if e.IsDir() || filepath.Ext(e.Name()) != ".db" {
					continue
				}
				info, err := e.Info()
				size := int64(0)
				if err == nil {
					size = info.Size()
				}
				dbs = append(dbs, sized{e.Name(), size})
			}
			sort.Slice(dbs, func(i, j int) bool { return config.CaptureNameLess(dbs[j].name, dbs[i].name) })
			fmt.Println("═══ SAVED CAPTURES ═══")
			for i, d := range dbs {
				if i == 20 {
					break
				}
				fmt.Printf("  %s (%.1f MB)\n", d.name, float64(d.size)/1_048_576)
			}
			if len(dbs) == 0 {
				fmt.Println("  (none yet)")
			}
			return nil
		},
	}
}

// ── version ─────────────────────────────────────────────────────────────────

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(version.String())
			return nil
		},
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// cliPrompter asks on the terminal; 'a' remembers approval. It reads from
// the SAME buffered stdin as the chat loop — a second reader would race for
// input and drop keystrokes.
type cliPrompter struct {
	in     *bufio.Reader
	always bool
}

func (p *cliPrompter) Allow(name string, args map[string]any) bool {
	if p.always {
		return true
	}
	parts := make([]string, 0, len(args))
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := args[k]
		if s, ok := v.(string); ok && len(s) > 40 {
			s := textutil.Truncate(s, 37) + "..."
			parts = append(parts, fmt.Sprintf("%s=%s", k, s))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	display := name + " " + strings.Join(parts, " ")
	const w = 58
	display = textutil.Truncate(display, w)
	pad := w - utf8.RuneCountInString(display)
	hbar := strings.Repeat("─", w+2)
	fmt.Println()
	fmt.Printf("  ┌%s┐\n", hbar)
	fmt.Printf("  │ %s%s │\n", display, strings.Repeat(" ", pad))
	fmt.Printf("  ├%s┤\n", hbar)
	fmt.Printf("  │ %-58s │\n", "[y] Allow   [a] Always   [n] Deny")
	fmt.Printf("  └%s┘\n", hbar)
	fmt.Print("  > ")
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "a", "always":
		p.always = true
		return true
	case "y", "yes":
		return true
	default:
		return false
	}
}
