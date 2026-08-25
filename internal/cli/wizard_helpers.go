package cli

import (
	"fmt"
)

func parseNonNeg(s string, def uint64) uint64 {
	var n uint64
	if s == "" {
		return def
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + uint64(c-'0')
		if n > 1<<32 {
			return def
		}
	}
	if n == 0 {
		return def
	}
	return n
}

// configTomlValues carries wizard answers into the generated file.
type configTomlValues struct {
	Interface string
	Target    string
	Duration  uint64
	Model     string
	NumCtx    int
	Stealth   int
	WebEnable bool
}

func renderConfigToml(v configTomlValues) string {
	webBlock := "enabled      = false"
	if v.WebEnable {
		webBlock = "enabled      = true\nprovider     = \"duckduckgo\""
	}
	return fmt.Sprintf(`# correlator configuration — written by correlator init

interface     = %q
target        = %q
duration      = %d

model         = %q          # top-level model override
num_ctx       = %d          # Ollama context window (2048..32768)

corporate_mode = false      # true hides game/streaming/cloud-sync detectors

[ai]
model   = %q
enabled = true

[web]
# OFFLINE BY DEFAULT. Internet access for AI tools requires explicit consent:
# enable here, or pass --allow-web to chat for one session.
%s
# provider     = "duckduckgo"   # duckduckgo | searxng | brave | tavily
# searxng_url     = "http://localhost:8888"
# brave_api_key   = "..."
# tavily_api_key  = "..."
`, v.Interface, v.Target, v.Duration, v.Model, v.NumCtx, v.Model, webBlock)
}
