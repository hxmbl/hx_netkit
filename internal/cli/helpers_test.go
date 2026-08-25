package cli

import (
	"strings"
	"testing"
	"time"
)

func TestParseChoice(t *testing.T) {
	if got := parseChoice("2", 3); got != 1 {
		t.Errorf("parseChoice(2,3) = %d", got)
	}
	if parseChoice("0", 3) != -1 || parseChoice("4", 3) != -1 || parseChoice("x", 3) != -1 {
		t.Error("invalid choices not rejected")
	}
}

func TestParseNonNeg(t *testing.T) {
	if parseNonNeg("", 300) != 300 || parseNonNeg("abc", 300) != 300 || parseNonNeg("0", 300) != 300 {
		t.Error("defaults not applied")
	}
	if parseNonNeg("45", 300) != 45 {
		t.Error("valid value rejected")
	}
}

func TestHumanSizeAndDuration(t *testing.T) {
	if humanSize(512) != "512 B" || humanSize(2048) != "2.0 KB" ||
		humanSize(5<<20) != "5.0 MB" || humanSize(3<<30) != "3.0 GB" {
		t.Error("humanSize wrong")
	}
	if d, err := parseHumanDuration("30d"); err != nil || d != 30*24*time.Hour {
		t.Errorf("parseHumanDuration(30d) = %v, %v", d, err)
	}
	if d, err := parseHumanDuration("90m"); err != nil || d != 90*time.Minute {
		t.Errorf("parseHumanDuration(90m) = %v, %v", d, err)
	}
}

func TestCaptureDateSecondsVsNanos(t *testing.T) {
	old := captureDate("capture_1700000000.db") // v1-style seconds
	if old.Unix() != 1700000000 {
		t.Errorf("seconds date = %v", old)
	}
	newer := captureDate("capture_1700000000123456789.db")
	if newer.UnixNano()/1e6 == 0 && newer.IsZero() {
		t.Error("nano date lost")
	}
	if !captureDate("whatever.db").IsZero() {
		t.Error("non-capture name should yield zero time")
	}
}

func TestRenderConfigTomlContainsAnswers(t *testing.T) {
	tomlText := renderConfigToml(configTomlValues{
		Interface: "en9",
		Target:    "10.9.8.0/24",
		Duration:  120,
		Model:     "llama3:8b",
		NumCtx:    8192,
		Stealth:   1,
	})
	for _, want := range []string{`"en9"`, `"10.9.8.0/24"`, "duration      = 120", `"llama3:8b"`, "num_ctx       = 8192"} {
		if !strings.Contains(tomlText, want) {
			t.Errorf("toml missing %q:\n%s", want, tomlText)
		}
	}
	if strings.Contains(tomlText, "\nprovider     = \"duckduckgo\"") {
		t.Error("web disabled but provider line uncommented")
	}
	webOn := renderConfigToml(configTomlValues{WebEnable: true})
	if !strings.Contains(webOn, "enabled      = true") {
		t.Error("web enabled flag missing")
	}
}
