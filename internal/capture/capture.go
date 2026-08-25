// Package capture orchestrates parallel TShark packet capture and nmap host
// discovery into a SQLite database.
package capture

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hxmbl/hx_netkit/internal/nmap"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/tshark"
	"github.com/hxmbl/hx_netkit/internal/ui"
)

// Options configures one capture run.
type Options struct {
	Interface    string
	Target       string
	DurationSecs uint64
	Fast         bool
	NoNmap       bool
	NoTShark     bool
	Debug        bool
	StealthLevel uint8
	DBPath       string
	Color        bool // styled output (defaults to plain)
	Out          io.Writer
}

func sudoCmd(prog string, args ...string) *exec.Cmd {
	isRoot := false
	if out, err := exec.Command("id", "-u").Output(); err == nil {
		isRoot = strings.TrimSpace(string(out)) == "0"
	}
	if isRoot {
		return exec.Command(prog, args...)
	}
	full := append([]string{prog}, args...)
	return exec.Command("sudo", full...)
}

// Run executes the capture and returns (packetsStored, devicesFound, error).
func Run(opts Options) (int, int, error) {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	fmt.Fprintln(out, "═══════ CAPTURE ═══════")
	fmt.Fprintf(out, "[System] Database: %s\n", opts.DBPath)
	level := "passive — TShark only, no active scanning"
	switch opts.StealthLevel {
	case nmap.StealthFull:
		level = "full scan — aggressive nmap, background scanner active"
	case nmap.StealthLight:
		level = "light — rate-limited scan, slower background scanner"
	}
	fmt.Fprintf(out, "[System] Stealth level: %d (%s)\n", opts.StealthLevel, level)

	db, err := store.Open(opts.DBPath)
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()

	var wg sync.WaitGroup
	stored := 0

	// ── nmap side ──
	if !opts.NoNmap && opts.StealthLevel <= nmap.StealthLight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			flags := nmap.Flags(opts.StealthLevel, opts.Fast, opts.Target)
			if flags == nil {
				return
			}
			fmt.Fprintf(out, "[System] Starting nmap scan of %s...\n", opts.Target)
			cmd := sudoCmd("nmap", flags...)
			var stderrBuf strings.Builder
			cmd.Stderr = &stderrBuf
			xmlOut, err := cmd.Output()
			if err != nil {
				msg := err.Error()
				if tail := strings.TrimSpace(stderrBuf.String()); tail != "" {
					msg += ": " + tail
				}
				hint := ""
				if _, lookErr := exec.LookPath("nmap"); lookErr != nil {
					hint = "\n[Hint] Install nmap first: brew install nmap (macOS) · apt install nmap (Debian/Ubuntu)"
				}
				fmt.Fprintf(out, "[Error] Failed to run nmap: %s.%s\n", msg, hint)
				return
			}
			if len(xmlOut) == 0 {
				return
			}
			now := float64(time.Now().UnixNano()) / 1e9
			devices := nmap.ParseXML(xmlOut)
			for _, d := range devices {
				if uerr := db.UpsertDevice(d.IP, d.MAC, d.Hostname, d.MACVendor, d.OSGuess, d.PortsString(), now); uerr != nil {
					fmt.Fprintf(out, "[Warn] device upsert failed for %s: %v\n", d.IP, uerr)
				}
			}
			summary := nmap.Summarize(devices)
			if rerr := db.RecordScan(opts.Target, string(xmlOut), summary, now); rerr != nil {
				fmt.Fprintf(out, "[Warn] scan record failed: %v\n", rerr)
			}
			fmt.Fprintf(out, "[nmap] Found %d devices:\n%s\n", len(devices), summary)
		}()
	} else {
		fmt.Fprintln(out, "[System] Skipping nmap (disabled or passive stealth).")
	}

	// ── tshark side ──
	if !opts.NoTShark {
		fmt.Fprintf(out, "[System] Starting TShark on %s for %ds...\n", opts.Interface, opts.DurationSecs)
		stored, err = runTShark(db, opts, out)
		if err != nil {
			wg.Wait()
			return stored, countDevices(db), err
		}
	}

	wg.Wait()

	devices := countDevices(db)
	fmt.Fprintf(out, "\n\n═══ CAPTURE COMPLETE ═══\n")
	fmt.Fprintf(out, "[System] %d packets captured, %d stored\n", stored, stored)
	fmt.Fprintf(out, "[System] %d devices in database\n", devices)
	fmt.Fprintf(out, "[System] Database saved at %s\n", opts.DBPath)
	store.UpdateLatestSymlink(opts.DBPath)
	fmt.Fprintln(out, "[System] Next steps:")
	fmt.Fprintf(out, "  correlator analyze          # behavioral findings for this capture\n")
	fmt.Fprintf(out, "  correlator chat             # ask the local AI about it\n")
	return stored, devices, nil
}

func countDevices(db *store.DB) int {
	s, err := db.Stats()
	if err != nil {
		return 0
	}
	return int(s.Devices)
}

func runTShark(db *store.DB, opts Options, out io.Writer) (int, error) {
	cmd := sudoCmd("tshark", tshark.Args(opts.Interface, "")...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("failed to pipe tshark stdout: %w", err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		msg := err.Error()
		if tail := strings.TrimSpace(stderrBuf.String()); tail != "" {
			msg += ": " + tail
		}
		return 0, fmt.Errorf("failed to start tshark: %s. Is it installed?", msg)
	}

	// Timer can be cancelled early when the stream ends on its own, and a
	// Ctrl-C interrupts tshark gracefully instead of killing the process —
	// the partial capture is finalized and summarized.
	timerStop := make(chan struct{})
	var timerOnce sync.Once
	defer timerOnce.Do(func() { close(timerStop) })
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		select {
		case <-time.After(time.Duration(opts.DurationSecs) * time.Second):
			interrupt(cmd)
		case <-timerStop:
		case <-sigCtx.Done():
			fmt.Fprintf(out, "\n[System] Ctrl-C — stopping capture early…\n")
			interrupt(cmd)
			timerOnce.Do(func() { close(timerStop) })
		}
	}()

	count := 0
	var totalBytes uint64
	progress := ui.NewProgress(out, "[cap]", time.Duration(opts.DurationSecs)*time.Second)
	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		rawLine := scanner.Text()
		if tshark.Skippable(rawLine) {
			continue
		}
		pkt, ok := tshark.ParseLine(rawLine)
		if !ok {
			continue
		}
		count++
		totalBytes += uint64(pkt.FrameLen)
		_ = db.InsertPacket(
			pkt.Epoch, pkt.IPSrc, pkt.IPDst,
			i64(pkt.TCPsrc), i64(pkt.TCPdst), i64(pkt.UDPsrc), i64(pkt.UDPdst),
			pkt.DNSQuery, strings.TrimSpace(rawLine), i64(pkt.FrameLen),
		)
		if opts.Debug {
			fmt.Fprintf(os.Stderr, "[debug] %s\n", rawLine)
		}
		progress.MaybeRender(uint64(count), totalBytes)
	}
	progress.Finish()
	kill(cmd)
	wait(cmd)

	if count == 0 {
		if tail := strings.TrimSpace(stderrBuf.String()); tail != "" {
			hint := "\n[Hint] If this is a permissions problem: run once with sudo, or grant dumpcap access"
			if _, lookErr := exec.LookPath("tshark"); lookErr != nil {
				hint = "\n[Hint] Install tshark first: brew install wireshark (macOS) · apt install tshark (Debian/Ubuntu)"
			}
			fmt.Fprintf(out, "\n[Warn] tshark produced no packets. stderr: %s%s\n", tail, hint)
		} else {
			fmt.Fprintln(out, "\n[Warn] No packets captured — was the interface idle? Try `correlator doctor`.")
		}
	}

	return count, nil
}

func interrupt(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}
}

// SudoTShark starts tshark with privilege escalation when needed.
func SudoTShark(args ...string) *exec.Cmd { return sudoCmd("tshark", args...) }

// Interrupt sends SIGINT to a running process.
func Interrupt(cmd *exec.Cmd) { interrupt(cmd) }

// Kill force-terminates a running process.
func Kill(cmd *exec.Cmd) { kill(cmd) }

// Wait reaps a finished child process.
func Wait(cmd *exec.Cmd) { wait(cmd) }

// StreamLines reads r line by line, invoking fn per line while fn returns true.
func StreamLines(r io.Reader, fn func(string) bool) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		if !fn(scanner.Text()) {
			break
		}
	}
	return scanner.Err()
}

func kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func wait(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_, _ = cmd.Process.Wait()
	}
}

func i64(v uint32) int64 { return int64(v) }
