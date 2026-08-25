package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hxmbl/hx_netkit/internal/belief"
	"github.com/hxmbl/hx_netkit/internal/config"
	ctxpkg "github.com/hxmbl/hx_netkit/internal/context"
	"github.com/hxmbl/hx_netkit/internal/llm"
	"github.com/hxmbl/hx_netkit/internal/nmap"
	"github.com/hxmbl/hx_netkit/internal/tools"
	"github.com/hxmbl/hx_netkit/internal/websearch"
)

type chatOptions struct {
	DBPath  string
	Model   string
	Stealth uint8
	Cfg     config.Config
	Web     config.Web
	AutoYes bool
}

func runChat(opts chatOptions) error {
	fmt.Println("\n═══════ NETWORK INTELLIGENCE ═══════")

	client := llm.New(opts.Cfg.OllamaURL, opts.Model, opts.Cfg.NumCtx)
	fmt.Printf("[System] Ollama: %s  model: %s  ctx: %d\n", client.BaseURL, opts.Model, opts.Cfg.NumCtx)
	if !client.TryStart(context.Background()) {
		fmt.Printf("[System] Ollama not available at %s. Entering search mode.\n", client.BaseURL)
		fmt.Println("[System] Use / prefix for search commands: /ip, /port, /dns, /find, /devices, /stats, /help")
		runSearchREPL(opts.DBPath, "")
		return nil
	}

	fmt.Printf("[System] Building context from %s\n", opts.DBPath)
	db := mustDB(opts.DBPath)
	defer db.Close()

	netCtx, err := ctxpkg.Build(db, opts.Cfg.CorporateMode)
	if err != nil {
		return err
	}

	beliefs := belief.New()
	beliefs.InitializeFromFindings(netCtx.Findings)
	for ip := range netCtx.Profiles {
		beliefs.Ensure(ip)
	}

	webClient := websearch.New(websearch.Config{
		Enabled:    opts.Web.Enabled,
		Provider:   opts.Web.Provider,
		SearXNGURL: opts.Web.SearXNG,
		BraveKey:   opts.Web.BraveKey,
		TavilyKey:  opts.Web.TavilyKey,
	})

	env := &tools.Env{
		DB:      db,
		Cfg:     opts.Cfg,
		Beliefs: beliefs,
		Web:     webClient,
		Context: netCtx,
	}

	scanner := llm.NewBackgroundScanner(beliefs, nmap.ExecRunner{}, opts.Stealth)
	defer scanner.Stop()

	var topIPs []string
	for i, f := range netCtx.Findings {
		if i == 5 {
			break
		}
		topIPs = append(topIPs, f.IP)
	}
	systemPrompt := fmt.Sprintf(`You are a network analyst. A capture summary is already in context (devices, stats, top talkers, findings).
For questions like "what's happening on the network?" or "which are bots?", answer from the summary first.
Use tools when the summary is insufficient: packets (evidence for an IP), sql, search, scan_ip, get_beliefs, nmap, tshark%s.
The packets tool is your direct line to raw packet data — use it to verify findings, trace connections, or investigate anomalies.
Never tell the user to run commands. Be brief and concrete.`,
		func() string {
			if webClient != nil {
				return ", websearch, webfetch"
			}
			return ""
		}())

	if topIPs == nil {
		topIPs = []string{"(none)"}
	}
	beliefContext := fmt.Sprintf(`

## Belief System
Each IP tracked with 5-category distribution: BOT, IOT, CAMERA, CLEAN, UNKNOWN.
Confidence is %% probability. Entropy bits = uncertainty level (higher = less certain).
IPs with <90%% confidence in any category are auto-scanned in background.
Top flagged IPs: %s. %d total IPs tracked.
Use get_beliefs tool to query current state.`,
		strings.Join(topIPs, ", "), beliefs.Len())

	firstUser := fmt.Sprintf("Loaded %d devices, %d packets, %d findings.\n\n%s%s",
		len(netCtx.Devices), netCtx.PacketCount, len(netCtx.Findings),
		netCtx.FormatForAI(), beliefContext)

	fmt.Printf("\n[System] Chat ready. %d devices, %d packets, %d findings loaded.\n",
		len(netCtx.Devices), netCtx.PacketCount, len(netCtx.Findings))
	fmt.Print("[System] Tools: packets, nmap, tshark, sql, search, scan_ip, get_beliefs, network_context, devices, anomalies, threats")
	if webClient != nil {
		fmt.Printf(", webfetch, websearch (--allow-web; provider: %s)", webClient.ProviderName())
	}
	fmt.Printf("\n[System] Belief tracker: scanning %d IPs in background (use /beliefs to see)\n", beliefs.Len())
	fmt.Println("[System] Type /help for commands. Ctrl-C cancels a line; Ctrl-D quits.")
	fmt.Println()

	// ONE buffered reader owns stdin; both the chat loop and the tool
	// permission prompter draw from it sequentially. Two independent
	// readers would race and swallow each other's input.
	stdin := bufio.NewReader(os.Stdin)

	session := &llm.Session{
		Client:    client,
		Env:       env,
		Beliefs:   beliefs,
		Events:    scanner,
		Prompter:  prompterFor(opts.AutoYes, stdin),
		Editor:    newEditorIfTTY(func() (llm.LineEditor, error) { return newChatEditor(db) }),
		SystemPmt: systemPrompt,
		In:        stdin,
		Out:       os.Stdout,
	}
	// Seed conversation with context.
	session.Seed(firstUser, "Got it. I can see your network and I'm tracking beliefs. What do you want to know?")
	session.Run(context.Background())
	fmt.Println("\n[System] Chat ended.")
	return nil
}

func prompterFor(autoYes bool, in *bufio.Reader) llm.Prompter {
	if autoYes {
		return llm.AlwaysAllow{}
	}
	return &cliPrompter{in: in}
}

// newEditorIfTTY constructs an interactive line editor only when stdin is a
// terminal; piped input keeps the plain buffered path (and tests keep working).
func newEditorIfTTY(make func() (llm.LineEditor, error)) llm.LineEditor {
	if !isTerminal(os.Stdin) {
		return nil
	}
	ed, err := make()
	if err != nil {
		return nil // readline unavailable — degrade silently
	}
	return ed
}

// ── live interpret ──────────────────────────────────────────────────────────

type liveOptions struct {
	Interface    string
	DurationSecs uint64
	NoSave       bool
	Output       string
	Verbose      bool
	UseAI        bool
	Model        string
	Cfg          config.Config
}

func runLiveInterpret(opts liveOptions) error {
	return captureLiveAndInterpret(opts)
}

func timeNowUnixNano() int64 { return time.Now().UnixNano() }
