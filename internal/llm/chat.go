package llm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hxmbl/hx_netkit/internal/belief"
	"github.com/hxmbl/hx_netkit/internal/nlsearch"
	"github.com/hxmbl/hx_netkit/internal/nmap"
	"github.com/hxmbl/hx_netkit/internal/tools"
)

// Seed pre-loads the conversation with grounding context before Run.
func (s *Session) Seed(userContent, assistantAck string) {
	s.messages = append(s.messages,
		Message{Role: "user", Content: userContent},
		Message{Role: "assistant", Content: assistantAck},
	)
}

// ScannerEvent feeds background scan activity into the chat UI.
type ScannerEvent struct {
	IP         string
	Alive      bool
	Ports      []uint32
	OSHint     string
	BeliefLine string
}

// EventSource yields pending scanner events without blocking.
type EventSource interface {
	Poll() []ScannerEvent
}

// Prompter asks the user to authorize a tool call.
type Prompter interface {
	Allow(name string, args map[string]any) bool
}

// AlwaysAllow auto-approves every call (used by --yes and tests).
type AlwaysAllow struct{}

// Allow implements Prompter.
func (AlwaysAllow) Allow(string, map[string]any) bool { return true }

// DenyAll rejects every call (tests).
type DenyAll struct{}

// Allow implements Prompter.
func (DenyAll) Allow(string, map[string]any) bool { return false }

// Session wires the chat loop together.
type Session struct {
	Client    *Client
	Env       *tools.Env
	Beliefs   *belief.System
	Events    EventSource // optional
	Prompter  Prompter
	WebOn     bool // live toggle for web tools
	SystemPmt string

	In  io.Reader
	Out io.Writer

	messages []Message
	scanner  *bufio.Scanner
}

// Run drives the interactive REPL until quit or EOF. Returns number of messages exchanged.
func (s *Session) Run(ctx context.Context) int {
	if s.Prompter == nil {
		s.Prompter = AlwaysAllow{}
	}
	s.scanner = bufio.NewScanner(s.In)
	s.scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	defs := tools.Definitions(s.Env.Web != nil)

	// Preserve any seeded conversation; guarantee a system preamble exists
	// exactly once, at position 0. (Seeds carry the grounded network brief.)
	switch {
	case len(s.messages) == 0:
		s.messages = []Message{{Role: "system", Content: s.SystemPmt}}
	case s.messages[0].Role != "system":
		s.messages = append([]Message{{Role: "system", Content: s.SystemPmt}}, s.messages...)
	}

	for {
		s.drainEvents()

		fmt.Fprint(s.Out, "you> ")
		if !s.scanner.Scan() {
			break
		}
		input := strings.TrimSpace(s.scanner.Text())
		if input == "" {
			continue
		}
		if input == "quit" || input == "exit" || input == "q" {
			break
		}
		if strings.HasPrefix(input, "/") {
			s.handleSlash(strings.TrimPrefix(input, "/"))
			continue
		}

		s.messages = append(s.messages, Message{Role: "user", Content: input})
		if !s.turn(ctx, defs) {
			s.messages = s.messages[:len(s.messages)-1]
			continue
		}
	}
	return len(s.messages)
}

func (s *Session) webEnabled() bool { return s.Env.Web != nil }

func (s *Session) drainEvents() {
	if s.Events == nil {
		return
	}
	for _, ev := range s.Events.Poll() {
		status := "down"
		if ev.Alive {
			status = "up"
		}
		ports := "no ports"
		if len(ev.Ports) > 0 {
			strs := make([]string, len(ev.Ports))
			for i, p := range ev.Ports {
				strs[i] = fmt.Sprint(p)
			}
			ports = "ports: [" + strings.Join(strs, " ") + "]"
		}
		os := ev.OSHint
		if os == "" {
			os = "no OS info"
		}
		fmt.Fprintf(s.Out, "  [Scanner] %s → %s (%s, %s)\n", ev.IP, status, ports, os)
		if ev.BeliefLine != "" {
			fmt.Fprintf(s.Out, "  [↻] %s\n", ev.BeliefLine)
		}
	}
}

func (s *Session) handleSlash(cmd string) {
	switch {
	case cmd == "beliefs" || cmd == "belief":
		if s.Beliefs == nil {
			fmt.Fprintln(s.Out, "  Belief system not initialized")
			return
		}
		fmt.Fprintln(s.Out, "═══ Beliefs ═══")
		fmt.Fprintln(s.Out, s.Beliefs.FormatAll())
	case strings.HasPrefix(cmd, "web"):
		arg := strings.TrimSpace(strings.TrimPrefix(cmd, "web"))
		switch arg {
		case "on":
			if s.Env.Web == nil {
				fmt.Fprintln(s.Out, "  Internet access is disabled in config; start correlator with --allow-web to permit it.")
				return
			}
			s.WebOn = true
			fmt.Fprintln(s.Out, "  [web] Internet access enabled for this session.")
		case "off":
			s.WebOn = false
			fmt.Fprintln(s.Out, "  [web] Internet access disabled for this session.")
		default:
			state := "off"
			if s.WebOn && s.Env.Web != nil {
				state = "on"
			}
			fmt.Fprintf(s.Out, "  Usage: /web on|off (currently %s)\n", state)
		}
	case strings.HasPrefix(cmd, "scan "):
		ip := strings.TrimSpace(strings.TrimPrefix(cmd, "scan "))
		if ip == "" {
			fmt.Fprintln(s.Out, "  Usage: /scan <IP>")
			return
		}
		if !tools.ValidTarget(ip) {
			fmt.Fprintf(s.Out, "  Invalid target: %s\n", ip)
			return
		}
		env := &tools.Env{DB: s.Env.DB, Cfg: s.Env.Cfg, Beliefs: s.Beliefs, ExecNmap: s.Env.ExecNmap}
		res := env.Execute(context.Background(), "scan_ip", map[string]any{"target": ip})
		fmt.Fprintf(s.Out, "  [Manual] %s\n", res.Summary)
	default:
		if !isSearchCommand(cmd) {
			fmt.Fprintln(s.Out, "  Unknown command. Available: /beliefs, /scan <IP>, /web on|off,")
			fmt.Fprintln(s.Out, "  or search commands like /stats, /ip <addr>, /dns <domain>, /help.")
			return
		}
		out := nlsearch.Execute(s.Env.DB, cmd)
		fmt.Fprint(s.Out, out)
		if out != "" && !strings.HasSuffix(out, "\n") {
			fmt.Fprintln(s.Out)
		}
	}
}

// isSearchCommand reports whether a slash command maps onto the non-AI
// search engine, so unknown commands get guidance instead of silently
// running a search.
func isSearchCommand(cmd string) bool {
	first := cmd
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		first = cmd[:i]
	}
	switch strings.ToLower(first) {
	case "help", "h", "?", "ip", "host", "port", "p", "dns", "d",
		"find", "f", "search", "s", "devices", "stats",
		"talkers", "top", "recent", "r", "connections", "conn", "services", "svc":
		return true
	}
	return false
}

func (s *Session) turn(ctx context.Context, defs []map[string]any) bool {
	activeDefs := defs
	if !(s.WebOn && s.Env.Web != nil) {
		filtered := make([]map[string]any, 0, len(defs))
		for _, d := range defs {
			if fnMap, ok := d["function"].(map[string]any); ok {
				if name, _ := fnMap["name"].(string); name == "websearch" || name == "webfetch" {
					continue
				}
			}
			filtered = append(filtered, d)
		}
		activeDefs = filtered
	}

	resp, err := s.streamChat(ctx, s.messages, activeDefs)
	if err != nil {
		fmt.Fprintf(s.Out, "\n[Error] %v\n", err)
		fmt.Fprintln(s.Out, "  [AI unavailable — try /help or 'quit']")
		return false
	}

	if len(resp.ToolCalls) == 0 {
		s.messages = append(s.messages, Message{Role: "assistant", Content: resp.Content})
		return true
	}

	assistant := Message{Role: "assistant", Content: resp.Content}
	assistant.ToolCalls = resp.ToolCalls
	s.messages = append(s.messages, assistant)

	for _, tc := range resp.ToolCalls {
		name := tc.Function.Name
		args := tc.Function.Arguments
		if args == nil {
			args = map[string]any{}
		}
		if !s.Prompter.Allow(name, args) {
			fmt.Fprintf(s.Out, "  [Tool denied]\n")
			s.messages = append(s.messages, Message{
				Role: "tool", ToolName: name,
				Content: fmt.Sprintf("[DENIED] User denied %s", name),
			})
			continue
		}
		result := s.Env.Execute(ctx, name, args)
		fmt.Fprintf(s.Out, "  [Tool: %s] %s\n", result.Name, result.Summary)
		s.messages = append(s.messages, Message{
			Role:     "tool",
			ToolName: name,
			Content:  fmt.Sprintf("[OK] %s: %s\n%s", result.Name, result.Summary, result.Output),
		})
	}

	follow, err := s.streamChat(ctx, s.messages, activeDefs)
	if err != nil {
		fmt.Fprintf(s.Out, "\n[Error] %v\n", err)
	} else if follow.Content != "" {
		s.messages = append(s.messages, Message{Role: "assistant", Content: follow.Content})
	}
	return true
}

// streamChat runs one completion while streaming tokens to the terminal as
// they arrive, so long generations don't look frozen.
func (s *Session) streamChat(ctx context.Context, msgs []Message, defs []map[string]any) (*Response, error) {
	printed := false
	prev := s.Client.OnToken
	s.Client.OnToken = func(tok string) {
		printed = true
		fmt.Fprint(s.Out, tok)
	}
	defer func() {
		s.Client.OnToken = prev
		if printed {
			fmt.Fprintln(s.Out)
		}
	}()
	return s.Client.Chat(ctx, msgs, defs)
}

// BackgroundScanner runs periodic belief-driven nmap probes until Stop is called.
type BackgroundScanner struct {
	Beliefs  *belief.System
	Runner   nmap.Runner
	Events   chan ScannerEvent
	stop     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

// NewBackgroundScanner spawns the loop when enabled for this stealth level.
func NewBackgroundScanner(b *belief.System, runner nmap.Runner, stealth uint8) *BackgroundScanner {
	bs := &BackgroundScanner{
		Beliefs: b,
		Runner:  runner,
		Events:  make(chan ScannerEvent, 16),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	if !nmap.BackgroundScannerEnabled(stealth) {
		close(bs.stopped)
		return bs
	}
	interval := time.Duration(nmap.BackgroundScannerInterval(stealth)) * time.Second
	ticker := time.NewTicker(interval)

	go func() {
		defer close(bs.stopped)
		defer ticker.Stop()
		for {
			select {
			case <-bs.stop:
				return
			case <-ticker.C:
			}
			if !bs.scanOnce() {
				return
			}
		}
	}()
	return bs
}

// scanOnce performs a single belief-driven probe. Returns false when the
// scanner should shut down. Split from the loop so tests can drive it
// deterministically without waiting on real ticker intervals.
func (bs *BackgroundScanner) scanOnce() bool {
	ip, _, ok := bs.Beliefs.PriorityIP(3)
	if !ok {
		return true
	}
	select {
	case <-bs.stop:
		return false
	default:
	}

	alive := pingUp(bs.Runner, ip)
	var ports []uint32
	if alive {
		ports = versionPorts(bs.Runner, ip)
	}
	osHint := ""
	if alive && len(ports) > 0 {
		osHint = nmap.GuessOSFromPorts(ports)
	}
	bs.Beliefs.UpdateFromNmap(ip, alive, ports)
	line, _ := bs.Beliefs.FormatIP(ip)
	ev := ScannerEvent{IP: ip, Alive: alive, Ports: ports, OSHint: osHint, BeliefLine: line}
	select {
	case bs.Events <- ev:
	default:
	}
	return true
}

// Poll drains queued scanner events.
func (bs *BackgroundScanner) Poll() []ScannerEvent {
	var out []ScannerEvent
	for {
		select {
		case ev := <-bs.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

// Stop signals the scanner to quit and waits up to 2 seconds for it. An
// in-flight nmap probe cannot be interrupted through the Runner interface,
// so Stop deliberately gives up after the grace period instead of blocking
// CLI exit forever; the goroutine exits at its next checkpoint or with the
// process.
func (bs *BackgroundScanner) Stop() {
	bs.stopOnce.Do(func() { close(bs.stop) })
	select {
	case <-bs.stopped:
	case <-time.After(2 * time.Second):
	}
}

func pingUp(r nmap.Runner, ip string) bool {
	out, err := r.Run("-sn", "-T5", "--max-retries", "1", "--host-timeout", "5s", ip)
	return err == nil && strings.Contains(string(out), "Host is up")
}

func versionPorts(r nmap.Runner, ip string) []uint32 {
	out, err := r.Run("-sV", "--top-ports", "100", "--open", "-oX", "-", "-T4", "--min-rate", "1000", ip)
	if err != nil {
		return nil
	}
	return nmap.ExtractOpenPorts(out)
}
