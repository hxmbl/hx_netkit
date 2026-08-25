package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hxmbl/hx_netkit/internal/config"
	"github.com/hxmbl/hx_netkit/internal/store"
)

type captureMeta struct {
	Path    string
	Name    string
	Seq     int64
	Size    int64
	Date    time.Time
	Packets uint64
	Devices uint64
	Scans   uint64
}

func captureDate(name string) time.Time {
	seq := captureSeqOf(name)
	if seq < 0 {
		return time.Time{}
	}
	if len(fmt.Sprint(seq)) >= 17 {
		return time.Unix(0, seq)
	}
	return time.Unix(seq, 0)
}

func listCaptureMetas(limit int) ([]captureMeta, error) {
	dir := config.CapturesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var metas []captureMeta
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".db" || e.Name() == "latest.db" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		info, err := e.Info()
		size := int64(0)
		if err == nil {
			size = info.Size()
		}
		m := captureMeta{Path: path, Name: e.Name(), Size: size, Date: captureDate(e.Name())}
		if db, err := store.OpenExisting(path); err == nil {
			if s, err := db.Stats(); err == nil {
				m.Packets, m.Devices, m.Scans = s.Packets, s.Devices, s.NmapScans
			}
			db.Close()
		}
		metas = append(metas, m)
	}
	sort.Slice(metas, func(i, j int) bool { return captureNameLess(metas[i].Name, metas[j].Name) })
	if limit > 0 && len(metas) > limit {
		metas = metas[len(metas)-limit:] // newest last → print reversed
	}
	return metas, nil
}

func newCapturesCmd(cfg config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "captures",
		Short: "Manage saved captures (list / info / prune)",
	}
	cmd.AddCommand(
		newCapturesListCmd(),
		newCapturesInfoCmd(),
		newCapturesPruneCmd(),
	)
	return cmd
}

func newCapturesListCmd() *cobra.Command {
	var limit int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show saved captures with dates and counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			metas, err := listCaptureMetas(limit)
			if err != nil {
				return nil // no captures dir yet
			}
			if asJSON {
				return json.NewEncoder(out).Encode(metas)
			}
			if len(metas) == 0 {
				fmt.Fprintln(out, "No captures yet — run `correlator run` or `correlator capture`.")
				return nil
			}
			fmt.Fprintf(out, "%-30s %-19s %9s %10s %8s\n", "CAPTURE", "DATE", "SIZE", "PACKETS", "DEVICES")
			for i := len(metas) - 1; i >= 0; i-- {
				m := metas[i]
				date := "—"
				if !m.Date.IsZero() {
					date = m.Date.Local().Format("2006-01-02 15:04")
				}
				fmt.Fprintf(out, "%-30s %-19s %8s %10d %8d\n",
					m.Name, date, humanSize(m.Size), m.Packets, m.Devices)
			}
			fmt.Fprintf(out, "\nOpen one with: correlator chat (%s picks the newest)\n",
				styleDimText("latest.db"))
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "how many newest to show")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func newCapturesInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <capture.db|latest>",
		Short: "Detail view for one capture",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			path, err := resolveCapturePath(args[0])
			if err != nil {
				return err
			}
			db, err := store.OpenExisting(path)
			if err != nil {
				return err
			}
			defer db.Close()

			s, _ := db.Stats()
			fmt.Fprintf(out, "═══ %s ═══\n", filepath.Base(path))
			fmt.Fprintf(out, "  Packets %d · Devices %d · DNS domains %d · Nmap scans %d\n",
				s.Packets, s.Devices, s.DNSDomains, s.NmapScans)

			if talkers, err := db.TopTalkers(5); err == nil && len(talkers) > 0 {
				fmt.Fprintln(out, "\n  Top talkers:")
				for _, t := range talkers {
					fmt.Fprintf(out, "    %-16s %d pkts\n", t.IP, t.Count)
				}
			}
			if devs, err := db.Devices(); err == nil && len(devs) > 0 {
				fmt.Fprintln(out, "\n  Known devices:")
				for _, d := range devs {
					host := ""
					if d.Hostname != nil {
						host = *d.Hostname
					}
					osG := ""
					if d.OSGuess != nil {
						osG = *d.OSGuess
					}
					fmt.Fprintf(out, "    %-16s (%s) %s [%s]\n", d.IP, host, osG, d.Ports)
				}
			}
			return nil
		},
	}
}

func newCapturesPruneCmd() *cobra.Command {
	var keep int
	var olderThan string
	var yes bool
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete old captures (--older-than 30d / --keep 5; dry-run unless --yes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			metas, err := listCaptureMetas(0)
			if err != nil || len(metas) == 0 {
				fmt.Fprintln(out, "Nothing to prune.")
				return nil
			}
			// oldest first
			sort.Slice(metas, func(i, j int) bool { return captureNameLess(metas[j].Name, metas[i].Name) })

			var cutoff time.Time
			if olderThan != "" {
				d, err := parseHumanDuration(olderThan)
				if err != nil {
					return fmt.Errorf("--older-than: %w (try 720h or 30d)", err)
				}
				cutoff = time.Now().Add(-d)
			}

			var victims []captureMeta
			for i, m := range metas {
				if keep > 0 && i >= len(metas)-keep {
					continue // inside the newest `keep`
				}
				if !cutoff.IsZero() && !m.Date.IsZero() && m.Date.After(cutoff) {
					continue
				}
				victims = append(victims, m)
			}
			if len(victims) == 0 {
				fmt.Fprintln(out, "Nothing to prune.")
				return nil
			}

			fmt.Fprintln(out, "Will delete:")
			var total int64
			for _, v := range victims {
				fmt.Fprintf(out, "  %-32s %8s  %s\n", v.Name, humanSize(v.Size), v.Date.Local().Format("2006-01-02 15:04"))
				total += v.Size
			}
			fmt.Fprintf(out, "  %d file(s), %s\n", len(victims), humanSize(total))

			if !yes {
				confirmed, ok := askYesNo(bufio.NewReader(cmd.InOrStdin()), out, "Delete these captures?", false)
				if !ok || !confirmed {
					fmt.Fprintln(out, "Aborted — nothing deleted.")
					return nil
				}
			}
			dir := config.CapturesDir()
			deleted := 0
			for _, v := range victims {
				for _, suffix := range []string{"", "-wal", "-shm"} {
					os.Remove(v.Path + suffix)
				}
				// Drop a dangling latest.db symlink.
				if link, err := os.Readlink(filepath.Join(dir, "latest.db")); err == nil && link == v.Path {
					os.Remove(filepath.Join(dir, "latest.db"))
				}
				deleted++
			}
			fmt.Fprintf(out, "Deleted %d capture(s).\n", deleted)
			return nil
		},
	}
	cmd.Flags().IntVar(&keep, "keep", 0, "always keep this many newest captures")
	cmd.Flags().StringVar(&olderThan, "older-than", "", "only delete captures older than this (720h or 30d)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "actually delete without asking")
	return cmd
}

func resolveCapturePath(arg string) (string, error) {
	if arg == "latest" {
		p, err := config.LatestDB()
		if err != nil {
			return "", fmt.Errorf("no captures yet — run `correlator run` or `correlator capture`")
		}
		return p, nil
	}
	if filepath.IsAbs(arg) {
		return arg, nil
	}
	p := filepath.Join(config.CapturesDir(), arg)
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	if _, err := os.Stat(arg); err == nil {
		return arg, nil
	}
	return "", fmt.Errorf("no such capture: %s (try `correlator captures list`)", arg)
}

// parseHumanDuration accepts Go durations plus a days suffix ("30d").
func parseHumanDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if d := strings.TrimSuffix(s, "d"); d != s {
		days, err := parseFloat(d)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
