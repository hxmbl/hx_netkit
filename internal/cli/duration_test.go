package cli

import (
	"bytes"
	"encoding/csv"
	"path/filepath"
	"strings"
	"testing"

	toml "github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/hxmbl/hx_netkit/internal/config"
	"github.com/hxmbl/hx_netkit/internal/store"
)

// `correlator init` asked for a stealth level and then silently dropped it:
// renderConfigToml never emitted the value and config.Config had no field for
// it, so capture/chat always ran at level 0 regardless of the answer.
func TestInitWizardPersistsStealthLevel(t *testing.T) {
	text := renderConfigToml(configTomlValues{Interface: "en0", Stealth: 2})
	if !strings.Contains(text, "stealth_level  = 2") {
		t.Errorf("stealth answer dropped from generated config:\n%s", text)
	}
	var cfg config.Config
	if err := toml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("generated config is not valid TOML: %v", err)
	}
	if cfg.StealthLevel != 2 {
		t.Errorf("StealthLevel = %d, want 2", cfg.StealthLevel)
	}
}

// The commands expose --stealth-level with the configured value as default.
func TestStealthFlagDefaultFromConfig(t *testing.T) {
	cfg := config.Config{StealthLevel: 1}
	if got := newCaptureCmd(cfg).Flags().Lookup("stealth-level").DefValue; got != "1" {
		t.Errorf("capture --stealth-level default = %q, want 1", got)
	}
	if got := newChatCmd(cfg).Flags().Lookup("stealth-level").DefValue; got != "1" {
		t.Errorf("chat --stealth-level default = %q, want 1", got)
	}
}

// --stealth-level is used as a uint8, so out-of-range values used to wrap:
// 256 became 0 (aggressive full scan + background scanner) and -1 became 255.
// Reject them instead of silently changing how hard the tool hits the network.
func TestStealthLevelRangeRejected(t *testing.T) {
	for _, v := range []int{0, 1, 2} {
		if got, err := clampStealth(v); err != nil || int(got) != v {
			t.Errorf("clampStealth(%d) = %d, %v; want %d, nil", v, got, err, v)
		}
	}
	for _, v := range []int{-1, 3, 99, 256, 257, 1000} {
		if _, err := clampStealth(v); err == nil {
			t.Errorf("clampStealth(%d) accepted an out-of-range level", v)
		}
	}
	// The uint8 wrap these values used to undergo must never reach the
	// scanner: 256 -> 0 is an aggressive full scan, -1 -> 255 is nonsense.
	for _, v := range []int{256, 257, -1} {
		if _, err := clampStealth(v); err == nil {
			t.Errorf("clampStealth(%d) let the uint8 wrap through", v)
		}
	}
}

// A zero capture duration means "stop before the first packet". It must be
// rejected instead of producing an empty capture (and, for `capture` with a
// tshark that ignores SIGINT, an indefinite hang).
func TestZeroDurationRejected(t *testing.T) {
	cfg := config.Config{} // nothing configured either
	cases := map[string]struct {
		cmd  *cobra.Command
		args []string
	}{
		"capture":        {newCaptureCmd(cfg), []string{"--no-nmap", "--no-tshark"}},
		"live-interpret": {newLiveInterpretCmd(cfg), nil},
	}
	for name, tc := range cases {
		c := tc.cmd
		c.SetArgs(tc.args)
		c.SilenceUsage = true
		c.SilenceErrors = true
		err := c.Execute()
		if err == nil || !strings.Contains(err.Error(), "duration") {
			t.Errorf("%s accepted a zero duration (err=%v)", name, err)
		}
	}
}

// --format csv must emit real CSV: packet fields contain commas, quotes and
// escaped quotes, which naive comma-joining turned into extra columns.
func TestQueryCSVOutputIsWellFormed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InsertPacket(1700000000, "10.0.0.5", "93.184.216.34", 40000, 443, 0, 0,
		`weird,domain"with space`, `{"raw":"a,b\"c"}`, 60); err != nil {
		t.Fatal(err)
	}

	cmd := newQueryCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"-d", path, "--format", "csv",
		"SELECT ip_src, dns_query, raw_json FROM packets"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v\n%s", err, buf.String())
	}
	if len(rows) != 2 {
		t.Fatalf("want header + 1 row, got %d:\n%s", len(rows), buf.String())
	}
	for i, r := range rows {
		if len(r) != 3 {
			t.Errorf("row %d has %d fields, want 3: %v", i, len(r), r)
		}
	}
	if rows[1][1] != `weird,domain"with space` {
		t.Errorf("dns_query mangled: %q", rows[1][1])
	}
}
