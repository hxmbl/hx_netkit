package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hxmbl/hx_netkit/internal/capture"
	"github.com/hxmbl/hx_netkit/internal/live"
	"github.com/hxmbl/hx_netkit/internal/store"
	"github.com/hxmbl/hx_netkit/internal/tshark"
	"github.com/hxmbl/hx_netkit/internal/ui"
)

// captureLiveAndInterpret streams TShark through the interpretation engine,
// printing per-packet insight. With --ai, the chat session runs WHILE the
// capture continues in the background (packets keep flowing into the DB),
// matching v1 semantics.
func captureLiveAndInterpret(opts liveOptions) error {
	fmt.Println("═══════ LIVE INTERPRET ═══════")
	fmt.Printf("[System] Interface: %s\n", opts.Interface)
	fmt.Printf("[System] Duration: %ds\n", opts.DurationSecs)
	fmt.Printf("[System] AI: %s\n", map[bool]string{true: "enabled (chat runs during capture)", false: "disabled (use --ai to enable)"}[opts.UseAI])
	fmt.Println("[System] Press Ctrl-C to stop early")

	dbPath := store.CapturePath(opts.NoSave, opts.Output)
	db, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	cmd := capture.SudoTShark(tshark.Args(opts.Interface, "")...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tshark: %w. Is it installed? (correlator doctor can help)", err)
	}

	engine := live.NewEngine()
	// The reader goroutine below keeps mutating the capture counters, the
	// interpretation engine and the progress meter until tshark's stdout
	// closes, while this goroutine prints the summary and drains the engine.
	// stateMu serializes those two halves, so the closing report can never be
	// computed from half-written state (and the reader can't still be
	// appending packets while Interpret walks the engine's maps).
	var stateMu sync.Mutex
	var count int
	var totalBytes uint64
	start := time.Now()

	// Ctrl-C stops tshark gracefully so partial captures are kept.
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		<-sigCtx.Done()
		fmt.Fprintf(os.Stderr, "\n[System] Ctrl-C — stopping capture early…\n")
		capture.Interrupt(cmd)
	}()

	done := make(chan struct{})
	progress := ui.NewProgress(os.Stdout, "[live]", capture.SecondsToDuration(opts.DurationSecs))
	go func() {
		defer close(done)
		_ = capture.StreamLines(stdoutPipe, func(rawLine string) bool {
			if tshark.Skippable(rawLine) {
				return true
			}
			pkt, ok := tshark.ParseLine(rawLine)
			if !ok {
				return true
			}
			var tcpDst *uint16
			if pkt.TCPdst > 0 {
				p := uint16(pkt.TCPdst)
				tcpDst = &p
			}
			stateMu.Lock()
			// A frame with no usable timestamp carries no timing evidence;
			// skip it entirely so the counters below match what is stored.
			if pkt.HasEpoch && pkt.Epoch > 0 && pkt.IPSrc != "" && pkt.IPDst != "" {
				engine.ProcessPacket(pkt.Epoch, pkt.IPSrc, pkt.IPDst, tcpDst, pkt.DNSQuery)
				err := db.InsertPacket(
					pkt.Epoch, pkt.IPSrc, pkt.IPDst,
					int64(pkt.TCPsrc), int64(pkt.TCPdst),
					int64(pkt.UDPsrc), int64(pkt.UDPdst),
					pkt.DNSQuery, strings.TrimSpace(rawLine), int64(pkt.FrameLen))
				if err == nil {
					count++
					totalBytes += uint64(pkt.FrameLen)
				} else {
					fmt.Fprintf(os.Stderr, "[Warn] packet insert failed: %v\n", err)
				}
			}

			if opts.Verbose {
				elapsed := time.Since(start).Seconds()
				switch {
				case pkt.DNSQuery != "":
					fmt.Printf("\r\x1b[K  %.1fs | %s → %s | DNS: %s\n",
						elapsed, orQ(pkt.IPSrc), orQ(pkt.IPDst), pkt.DNSQuery)
				case pkt.TCPdst > 0:
					fmt.Printf("\r\x1b[K  %.1fs | %s → %s:%d (%s)\n",
						elapsed, orQ(pkt.IPSrc), orQ(pkt.IPDst), pkt.TCPdst, live.ServiceName(uint16(pkt.TCPdst)))
				}
			} else if !opts.UseAI {
				progress.MaybeRender(uint64(count), totalBytes)
			}
			stateMu.Unlock()
			return true
		})
	}()

	// Watchdog: stop the stream once the requested duration elapses.
	watchdog := time.AfterFunc(capture.SecondsToDuration(opts.DurationSecs), func() {
		capture.Interrupt(cmd)
	})

	if opts.UseAI {
		cfg := opts.Cfg
		if err := runChat(chatOptions{
			DBPath:  dbPath,
			Model:   opts.Model,
			Stealth: 2, // passive while chatting on top of live capture
			Cfg:     cfg,
			Web:     cfg.Web,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "[Error] chat: %v\n", err)
		}
	} else {
		select {
		case <-done:
		case <-time.After(capture.SecondsToDuration(opts.DurationSecs) + 2*time.Second):
			// watchdog already fired; give the reader a moment to drain
		}
	}

	capture.Interrupt(cmd)
	stateMu.Lock()
	progress.Finish()
	stateMu.Unlock()
	capture.Kill(cmd)
	capture.Wait(cmd)
	watchdog.Stop()
	// Killing the child closes its stdout, which ends the reader goroutine.
	// Wait for it before touching any of the state it was mutating.
	<-done

	stateMu.Lock()
	defer stateMu.Unlock()
	fmt.Printf("\n\n═══ CAPTURE COMPLETE ═══\n")
	fmt.Printf("[System] %d packets captured, %d stored\n", count, count)

	inters := engine.Interpret()
	if len(inters) > 0 {
		fmt.Println("\n═══ INTERPRETATION ═══")
		for _, it := range inters {
			fmt.Println("  " + it.Desc)
		}
	}

	store.UpdateLatestSymlink(dbPath)
	fmt.Printf("\n[System] Database saved at %s\n", dbPath)
	fmt.Println("[System] Next steps:")
	fmt.Println("  correlator analyze          # behavioral findings for this capture")
	fmt.Println("  correlator chat             # ask the local AI about it")
	return nil
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
