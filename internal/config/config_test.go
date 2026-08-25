package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigNormalization(t *testing.T) {
	cfg := defaultConfig()
	cfg.normalize()

	if cfg.Interface != DefaultInterface {
		t.Errorf("interface = %q, want %q", cfg.Interface, DefaultInterface)
	}
	if cfg.Target != DefaultTarget {
		t.Errorf("target = %q, want %q", cfg.Target, DefaultTarget)
	}
	if cfg.Duration != DefaultDuration {
		t.Errorf("duration = %d, want %d", cfg.Duration, DefaultDuration)
	}
	if cfg.OllamaURL != DefaultOllamaURL {
		t.Errorf("ollama_url = %q", cfg.OllamaURL)
	}
	if !cfg.AI.Enabled {
		t.Error("AI should be enabled by default")
	}
	if cfg.Web.Provider != "duckduckgo" {
		t.Errorf("web provider = %q, want duckduckgo", cfg.Web.Provider)
	}
	if cfg.Web.Enabled {
		t.Error("web must be disabled by default (offline-first)")
	}
}

func TestNumCtxClamped(t *testing.T) {
	cfg := defaultConfig()
	cfg.NumCtx = 100
	cfg.normalize()
	if cfg.NumCtx != 2048 {
		t.Errorf("num_ctx = %d, want clamp to 2048", cfg.NumCtx)
	}
	cfg.NumCtx = 999999
	cfg.normalize()
	if cfg.NumCtx != 32768 {
		t.Errorf("num_ctx = %d, want clamp to 32768", cfg.NumCtx)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
interface = "eth9"
target = "10.0.0.0/24"
duration = 60
model = "llama3:8b"
ollama_url = "http://192.168.1.5:11434"
num_ctx = 4096
corporate_mode = true

[ai]
model = "mistral:7b"

[web]
enabled = true
provider = "searxng"
searxng_url = "http://localhost:8888"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(path)
	if !cfg.Loaded() {
		t.Fatal("config should be marked loaded")
	}
	if cfg.Interface != "eth9" || cfg.Target != "10.0.0.0/24" || cfg.Duration != 60 {
		t.Errorf("basic fields not loaded: %+v", cfg)
	}
	if cfg.Model != "llama3:8b" {
		t.Errorf("model = %q", cfg.Model)
	}
	if cfg.AI.Model != "mistral:7b" {
		t.Errorf("ai.model = %q", cfg.AI.Model)
	}
	if cfg.CorporateMode != true {
		t.Error("corporate_mode not loaded")
	}
	if !cfg.Web.Enabled || cfg.Web.Provider != "searxng" || cfg.Web.SearXNG == "" {
		t.Errorf("web section not loaded: %+v", cfg.Web)
	}
}

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	cfg := loadFrom(filepath.Join(t.TempDir(), "nope.toml"))
	if cfg.Loaded() {
		t.Error("missing file must not mark config as loaded")
	}
	if cfg.Interface != DefaultInterface {
		t.Errorf("expected defaults, got %+v", cfg)
	}
}

func TestResolveModelPrecedence(t *testing.T) {
	base := defaultConfig()

	if got := ResolveModel("", base); got != DefaultModel {
		t.Errorf("default resolve = %q", got)
	}
	if got := ResolveModel("cli-model", base); got != "cli-model" {
		t.Errorf("cli override ignored: %q", got)
	}

	top := defaultConfig()
	top.Model = "hermes3:8b"
	top.AI.Model = "stale-model"
	if got := ResolveModel("", top); got != "hermes3:8b" {
		t.Errorf("custom top-level model should win over ai.model, got %q", got)
	}

	onlyAI := defaultConfig()
	onlyAI.AI.Model = "qwen3:8b"
	if got := ResolveModel("", onlyAI); got != "qwen3:8b" {
		t.Errorf("ai.model fallback failed, got %q", got)
	}
}

func TestLatestDBPrefersSymlinkAndSorts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	os.MkdirAll(CapturesDir(), 0o755)

	if _, err := LatestDB(); err == nil {
		t.Fatal("expected error when no captures exist")
	}

	for _, name := range []string{"capture_100.db", "capture_200.db"} {
		os.WriteFile(filepath.Join(CapturesDir(), name), []byte{}, 0o600)
	}
	got, err := LatestDB()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "capture_200.db" {
		t.Errorf("latest = %q, want capture_200.db", got)
	}

	// symlink wins
	os.WriteFile(filepath.Join(dir, "target.db"), []byte{}, 0o600)
	os.Symlink(filepath.Join(dir, "target.db"), filepath.Join(CapturesDir(), "latest.db"))
	got, err = LatestDB()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "latest.db" {
		t.Errorf("symlink not preferred, got %q", got)
	}
}
