// Package config loads correlator configuration from TOML files.
//
// Search order (first match wins):
//
//	./correlator.toml
//	~/.correlator/config.toml
//	/etc/correlator/config.toml
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	toml "github.com/BurntSushi/toml"
)

// Web controls optional internet access for AI tools.
// The tool is offline-first: web access is disabled unless explicitly
// enabled here or via --allow-web on the command line.
type Web struct {
	Enabled   bool   `toml:"enabled"`
	Provider  string `toml:"provider"` // duckduckgo | searxng | brave | tavily
	SearXNG   string `toml:"searxng_url"`
	BraveKey  string `toml:"brave_api_key"`
	TavilyKey string `toml:"tavily_api_key"`
}

// Config mirrors correlator.toml.
type Config struct {
	Interface     string `toml:"interface"`
	Target        string `toml:"target"`
	Duration      uint64 `toml:"duration"`
	Model         string `toml:"model"`
	OllamaURL     string `toml:"ollama_url"`
	NumCtx        int    `toml:"num_ctx"`
	CorporateMode bool   `toml:"corporate_mode"`
	AI            AI     `toml:"ai"`
	Web           Web    `toml:"web"`

	loaded bool
}

type AI struct {
	Model   string `toml:"model"`
	Enabled bool   `toml:"enabled"`
}

// Defaults used when no config file is found or a key is missing.
const (
	DefaultInterface = "en1"
	DefaultTarget    = "192.168.1.0/24"
	DefaultDuration  = 300
	DefaultModel     = "qwen3:4b"
	DefaultOllamaURL = "http://localhost:11434"
	DefaultNumCtx    = 12288
)

// Dir returns the per-user data directory (~/.correlator).
func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "correlator")
	}
	return filepath.Join(home, ".correlator")
}

// CapturesDir returns the capture database directory.
func CapturesDir() string { return filepath.Join(Dir(), "captures") }

func defaultConfig() Config {
	return Config{
		Interface: DefaultInterface,
		Target:    DefaultTarget,
		Duration:  DefaultDuration,
		Model:     DefaultModel,
		OllamaURL: DefaultOllamaURL,
		NumCtx:    DefaultNumCtx,
		AI:        AI{Model: DefaultModel, Enabled: true},
	}
}

var searchPaths = []string{
	"correlator.toml",
}

// Load reads the first config file it finds, falling back to defaults.
// Missing keys inherit defaults; malformed files are ignored.
func Load() Config {
	paths := append([]string{}, searchPaths...)
	paths = append(paths,
		filepath.Join(Dir(), "config.toml"),
		"/etc/correlator/config.toml",
	)
	for _, p := range paths {
		if cfg, ok := loadIfReadable(p); ok {
			return cfg
		}
	}
	cfg := defaultConfig()
	cfg.normalize()
	return cfg
}

// loadFrom loads one specific config file (used by tests and future -c flag).
func loadFrom(path string) Config {
	if cfg, ok := loadIfReadable(path); ok {
		return cfg
	}
	cfg := defaultConfig()
	cfg.normalize()
	return cfg
}

func loadIfReadable(path string) (Config, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, false
	}
	cfg := defaultConfig()
	if err := toml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[config] ignoring invalid TOML in %s: %v\n", path, err)
		return Config{}, false
	}
	cfg.loaded = true
	cfg.normalize()
	return cfg, true
}

// Loaded reports whether any config file was actually read.
func (c Config) Loaded() bool { return c.loaded }

func (c *Config) normalize() {
	if c.OllamaURL == "" {
		c.OllamaURL = DefaultOllamaURL
	}
	if c.NumCtx < 2048 {
		c.NumCtx = 2048
	}
	if c.NumCtx > 32768 {
		c.NumCtx = 32768
	}
	if c.Web.Provider == "" {
		c.Web.Provider = "duckduckgo"
	}
}

// ResolveModel picks the Ollama model: explicit CLI flag wins, then a
// customized top-level model, then [ai].model.
func ResolveModel(cliModel string, cfg Config) string {
	if cliModel != "" {
		return cliModel
	}
	if cfg.Model != DefaultModel {
		return cfg.Model
	}
	if cfg.AI.Model != "" {
		return cfg.AI.Model
	}
	return DefaultModel
}

// LatestDB returns the most recent capture database in the captures dir,
// preferring the latest.db symlink when present. Ordering is numeric
// (capture_<unix>.db), so capture_100 beats capture_99.
func LatestDB() (string, error) {
	link := filepath.Join(CapturesDir(), "latest.db")
	if fi, err := os.Stat(link); err == nil && !fi.IsDir() {
		return link, nil
	}
	entries, err := os.ReadDir(CapturesDir())
	if err != nil {
		return "", err
	}
	var best string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".db" {
			continue
		}
		name := e.Name()
		if best == "" || CaptureNameLess(best, name) {
			best = name
		}
	}
	if best == "" {
		return "", os.ErrNotExist
	}
	return filepath.Join(CapturesDir(), best), nil
}

// CaptureNameLess orders capture file names newest-first-friendly: files
// matching capture_<number>.db sort by their number; anything else falls
// back to plain lexicographic order.
func CaptureNameLess(a, b string) bool {
	sa, sb := CaptureSeq(a), CaptureSeq(b)
	if sa != sb {
		return sa < sb
	}
	return a < b
}

// CaptureSeq extracts the numeric portion of a capture_*.db name (-1 when
// the name doesn't follow the pattern).
func CaptureSeq(name string) int64 {
	base := strings.TrimSuffix(name, ".db")
	base = strings.TrimPrefix(base, "capture_")
	n, err := strconv.ParseInt(base, 10, 64)
	if err != nil {
		return -1
	}
	return n
}
