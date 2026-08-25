// Package websearch provides opt-in internet access for AI tools.
//
// The correlator is offline-first: nothing here is reachable unless the user
// enables it via config ([web] enabled = true) or --allow-web. Providers are
// pluggable; the zero-config default is DuckDuckGo Lite HTML scraping, which
// requires no API key or account.
//
// Security posture: every outbound request — including each redirect hop —
// is screened against private/loopback/link-local address ranges, and the
// transport resolves hostnames itself so DNS rebinding cannot smuggle a
// public-looking hostname to an internal address.
package websearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hxmbl/hx_netkit/internal/textutil"
)

// Result is one search hit.
type Result struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet,omitempty"`
}

// Searcher queries the web for results.
type Searcher interface {
	Search(ctx context.Context, query string) ([]Result, error)
	Name() string
}

// Fetcher retrieves a page as trimmed text.
type Fetcher interface {
	Fetch(ctx context.Context, rawURL string) (string, int, error)
}

// Client performs search + fetch against an allow-listed provider set.
//
// Two HTTP clients with different trust levels:
//   - providerHTTP: plain; used for search endpoints the USER configured
//     (self-hosted SearXNG on the LAN is legitimate).
//   - http: hardened (redirect-screened, dial-guarded); used by webfetch,
//     where the MODEL controls the target URL.
type Client struct {
	http         *http.Client // hardened — model-controlled URLs
	providerHTTP *http.Client // plain — user-configured endpoints only
	Search       Searcher
}

// Config mirrors [web] in correlator.toml.
type Config struct {
	Enabled    bool
	Provider   string // duckduckgo | searxng | brave | tavily
	SearXNGURL string
	BraveKey   string
	TavilyKey  string
}

// ProviderName reports which searcher is actually in use (after any
// fallback), so the UI can tell the user the truth.
func (c *Client) ProviderName() string {
	if c == nil || c.Search == nil {
		return "none"
	}
	return c.Search.Name()
}

// New builds a client for cfg. Returns nil when web access is disabled —
// callers must treat that as "tool not available". A configured provider
// that lacks its required settings falls back to DuckDuckGo with a visible
// warning rather than silently pretending otherwise.
func New(cfg Config) *Client {
	if !cfg.Enabled {
		return nil
	}
	c := &Client{
		http:         newHardenedHTTP(),
		providerHTTP: &http.Client{Timeout: 15 * time.Second},
	}
	requested := strings.ToLower(cfg.Provider)
	switch requested {
	case "searxng":
		if cfg.SearXNGURL != "" {
			c.Search = searxng{base: strings.TrimRight(cfg.SearXNGURL, "/"), http: c.providerHTTP}
		}
	case "brave":
		if cfg.BraveKey != "" {
			c.Search = brave{key: cfg.BraveKey, http: c.providerHTTP}
		}
	case "tavily":
		if cfg.TavilyKey != "" {
			c.Search = tavily{key: cfg.TavilyKey, http: c.providerHTTP}
		}
	default:
		requested = "duckduckgo"
	}
	if c.Search == nil {
		if requested != "" && requested != "duckduckgo" {
			fmt.Fprintf(os.Stderr, "[web] provider %q is missing its configuration; falling back to duckduckgo\n", requested)
		}
		c.Search = duckduckgo{http: c.providerHTTP}
	}
	return c
}

// newHardenedHTTP builds the shared HTTP client with SSRF guards:
// every redirect hop is re-validated, and all dials resolve hostnames
// through a screening resolver so private addresses are unreachable even
// when reached via rebinding or redirects.
func newHardenedHTTP() *http.Client {
	dialer := &ssrfGuard{
		resolver: net.Resolver{},
		dialer:   &net.Dialer{Timeout: 10 * time.Second},
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			// Keep parity with Go's default transport so HTTP(S)_PROXY
			// setups keep working through the guard.
			Proxy: http.ProxyFromEnvironment,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if err := ValidateURLHost(req.URL); err != nil {
				return fmt.Errorf("blocked redirect to %s: %w", redactHost(req.URL), err)
			}
			return nil
		},
	}
}

func redactHost(u *url.URL) string {
	host := u.Hostname()
	if isLocalHost(host) {
		return "<internal-address>"
	}
	return host
}

func get(ctx context.Context, h *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; hxnetkit-correlator/2.0)")
	resp, err := h.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return body, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ── DuckDuckGo Lite ─────────────────────────────────────────────────────────

type duckduckgo struct{ http *http.Client }

func (d duckduckgo) Name() string { return "duckduckgo" }

func (d duckduckgo) Search(ctx context.Context, query string) ([]Result, error) {
	target := "https://lite.duckduckgo.com/lite/?q=" + url.QueryEscape(query)
	body, status, err := get(ctx, d.http, target)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("search provider returned %d", status)
	}
	results := parseDDGLite(string(body))
	if len(results) > 5 {
		results = results[:5]
	}
	return results, nil
}

// ParseDDGLite extracts result links/snippets from DDG Lite HTML.
func ParseDDGLite(page string) []Result { return parseDDGLite(page) }

// parseDDGLite extracts results from DuckDuckGo Lite HTML.
//
// Structure per hit: an anchor `<a rel="nofollow" href="...">Title</a>` whose
// href is a //duckduckgo.com/l/?uddg=<urlencoded> redirect, optionally followed
// by a `<td class='result__snippet'>…</td>` cell.
func parseDDGLite(page string) []Result {
	const anchor = "<a rel=\"nofollow\" href=\""
	var out []Result
	pos := 0
	for len(out) < 8 {
		start := strings.Index(page[pos:], anchor)
		if start < 0 {
			break
		}
		start += pos + len(anchor)

		hrefEnd := strings.Index(page[start:], "\"")
		if hrefEnd < 0 {
			break
		}
		href := page[start : start+hrefEnd]

		gt := strings.Index(page[start+hrefEnd:], ">")
		if gt < 0 {
			break
		}
		titleStart := start + hrefEnd + gt + 1
		aEnd := strings.Index(page[titleStart:], "</a>")
		if aEnd < 0 {
			break
		}
		title := stripTags(page[titleStart : titleStart+aEnd])

		link := decodeDDGHref(href)
		snippet := ""
		if link != "" && title != "" {
			after := titleStart + aEnd
			sIdx := strings.Index(page[after:], "result__snippet")
			if sIdx < 0 {
				sIdx = strings.Index(page[after:], "result-snippet")
			}
			if sIdx >= 0 {
				tail := page[after+sIdx:]
				sStart := strings.Index(tail, ">")
				sEnd := strings.Index(tail, "</td>")
				if sStart >= 0 && sEnd > sStart {
					snippet = stripTags(tail[sStart+1 : sEnd])
				}
			}
			out = append(out, Result{Title: title, URL: link, Snippet: snippet})
		}

		pos = titleStart + aEnd
	}
	return dedupe(out)
}

// decodeDDGHref unwraps DDG's //duckduckgo.com/l/?uddg=<encoded> redirects.
// DuckDuckGo-internal links without an uddg target are dropped (empty string).
func decodeDDGHref(href string) string {
	href = html.UnescapeString(href)
	isDDG := strings.HasPrefix(href, "//duckduckgo.com/") || strings.HasPrefix(href, "https://duckduckgo.com/")
	if isDDG {
		idx := strings.Index(href, "uddg=")
		if idx < 0 {
			return ""
		}
		rest := href[idx+len("uddg="):]
		if end := strings.Index(rest, "&"); end >= 0 {
			rest = rest[:end]
		}
		if decoded, err := url.QueryUnescape(rest); err == nil {
			return decoded
		}
		return ""
	}
	return href
}

func stripTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	out := html.UnescapeString(b.String())
	return strings.Join(strings.Fields(out), " ")
}

func dedupe(rs []Result) []Result {
	seen := map[string]bool{}
	var out []Result
	for _, r := range rs {
		if seen[r.URL] || seen[r.Title] {
			continue
		}
		seen[r.URL] = true
		seen[r.Title] = true
		out = append(out, r)
	}
	return out
}

// ── SearXNG (self-hosted JSON API) ──────────────────────────────────────────

type searxng struct {
	base string
	http *http.Client
}

func (s searxng) Name() string { return "searxng" }

type searxngResponse struct {
	Results []struct {
		Title   string `json:"title"`
		URL     string `json:"url"`
		Content string `json:"content"`
	} `json:"results"`
}

func (s searxng) Search(ctx context.Context, query string) ([]Result, error) {
	target := fmt.Sprintf("%s/search?q=%s&format=json", s.base, url.QueryEscape(query))
	body, _, err := get(ctx, s.http, target)
	if err != nil {
		return nil, err
	}
	var parsed searxngResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("searxng returned non-JSON response: %w", err)
	}
	var out []Result
	for i, r := range parsed.Results {
		if i == 5 {
			break
		}
		out = append(out, Result{Title: r.Title, URL: r.URL, Snippet: r.Content})
	}
	return out, nil
}

// ── Brave Search API ────────────────────────────────────────────────────────

type brave struct {
	key  string
	http *http.Client
}

func (b brave) Name() string { return "brave" }

type braveResponse struct {
	Web struct {
		Results []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
		} `json:"results"`
	} `json:"web"`
}

func (b brave) Search(ctx context.Context, query string) ([]Result, error) {
	target := "https://api.search.brave.com/res/v1/web/search?q=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Subscription-Token", b.key)
	req.Header.Set("Accept", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("brave returned %d", resp.StatusCode)
	}
	var parsed braveResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	var out []Result
	for i, r := range parsed.Web.Results {
		if i == 5 {
			break
		}
		out = append(out, Result{Title: r.Title, URL: r.URL, Snippet: r.Description})
	}
	return out, nil
}

// ── Tavily ──────────────────────────────────────────────────────────────────

type tavily struct {
	key  string
	http *http.Client
}

func (t tavily) Name() string { return "tavily" }

type tavilyRequest struct {
	Query string `json:"query"`
}

type tavilyResponse struct {
	Results []struct {
		Title   string `json:"title"`
		URL     string `json:"url"`
		Content string `json:"content"`
	} `json:"results"`
}

func (t tavily) Search(ctx context.Context, query string) ([]Result, error) {
	payload, _ := json.Marshal(tavilyRequest{Query: query})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tavily.com/search", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tavily returned %d", resp.StatusCode)
	}
	var parsed tavilyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	var out []Result
	for i, r := range parsed.Results {
		if i == 5 {
			break
		}
		out = append(out, Result{Title: r.Title, URL: r.URL, Snippet: r.Content})
	}
	return out, nil
}

// ── SSRF guards ─────────────────────────────────────────────────────────────

// ValidateURLHost screens a URL's host against internal address ranges.
func ValidateURLHost(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("missing host")
	}
	if isLocalHost(host) {
		return errors.New("refusing to fetch local addresses")
	}
	return nil
}

// ssrfGuard is a net.Dialer wrapper that resolves the target hostname and
// refuses connections to internal addresses. Because every request —
// original or redirected — dials through it, neither redirects nor DNS
// rebinding can reach private space.
type ssrfGuard struct {
	resolver net.Resolver
	dialer   *net.Dialer
}

func (g *ssrfGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("blocked: bad dial address %q", addr)
	}
	if err := g.validateHost(ctx, host); err != nil {
		return nil, err
	}
	return g.dialer.DialContext(ctx, network, addr)
}

func (g *ssrfGuard) validateHost(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isInternalIP(ip) {
			return fmt.Errorf("blocked: refusing to connect to %s", host)
		}
		return nil
	}
	if isLocalHost(host) {
		return fmt.Errorf("blocked: refusing to connect to %s", host)
	}
	addrs, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("blocked: cannot resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("blocked: no addresses for %s", host)
	}
	for _, a := range addrs {
		if isInternalIP(a.IP) {
			return fmt.Errorf("blocked: %s resolves to internal address %s", host, a.IP)
		}
	}
	return nil
}

// isInternalIP covers loopback, RFC1918/CGNAT/private v6, link-local,
// unspecified, and multicast ranges.
func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// ── Fetch ───────────────────────────────────────────────────────────────────

// FetchPage downloads a page and returns readable text capped at maxBytes.
// The initial URL, every redirect hop, and every resolved IP are screened
// against internal ranges (see newHardenedHTTP).
func (c *Client) FetchPage(ctx context.Context, rawURL string, maxBytes int64) (string, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", 0, fmt.Errorf("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", 0, fmt.Errorf("URL must start with http:// or https://")
	}
	// Fast front-door check; the transport re-checks every hop.
	if isLocalHost(u.Hostname()) {
		return "", 0, fmt.Errorf("blocked: refusing to fetch local addresses")
	}
	body, status, err := get(ctx, c.http, rawURL)
	if err != nil {
		return "", status, err
	}
	text := ExtractText(string(body))
	if int64(len(text)) > maxBytes {
		text = textutil.Truncate(text, int(maxBytes))
	}
	return text, status, nil
}

func isLocalHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".local") || host == "0.0.0.0" {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		octets := make([]int, 4)
		ok := true
		for i, p := range parts {
			n := 0
			if p == "" {
				ok = false
				break
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					ok = false
				}
				n = n*10 + int(c-'0')
				if n > 255 {
					ok = false
				}
			}
			octets[i] = n
		}
		if ok {
			if octets[0] == 10 || octets[0] == 127 || octets[0] == 169 && octets[1] == 254 ||
				(octets[0] == 192 && octets[1] == 168) ||
				(octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) {
				return true
			}
		}
	}
	return false
}

// ExtractText strips scripts/styles/tags down to readable words.
func ExtractText(page string) string {
	lower := strings.ToLower(page)
	var b strings.Builder
	write := true
	i := 0
	for i < len(page) {
		if strings.HasPrefix(lower[i:], "<script") {
			end := indexFold(page, i, "</script>")
			if end < 0 {
				break
			}
			i = end + len("</script>")
			write = true
			continue
		}
		if strings.HasPrefix(lower[i:], "<style") {
			end := indexFold(page, i, "</style>")
			if end < 0 {
				break
			}
			i = end + len("</style>")
			write = true
			continue
		}
		if page[i] == '<' {
			write = false
			i++
			continue
		}
		if page[i] == '>' {
			write = true
			i++
			b.WriteByte(' ') // tag boundaries separate words
			continue
		}
		if write {
			b.WriteByte(page[i])
		}
		i++
	}
	out := html.UnescapeString(b.String())
	fields := strings.Fields(out)
	return strings.Join(fields, " ")
}

func indexFold(s string, start int, sub string) int {
	idx := strings.Index(strings.ToLower(s[start:]), sub)
	if idx < 0 {
		return len(s)
	}
	return idx + start
}
