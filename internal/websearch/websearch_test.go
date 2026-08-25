package websearch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const ddgFixture = `<!DOCTYPE html>
<html><body>
<tr><td>1.&nbsp;</td><td>
<a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.example.com%2Fguide&amp;rut=abc" class='result-link'>Example Guide</a>
</td></tr>
<tr><td class='result-snippet'>A guide about <b>examples</b> and testing.</td></tr>
<tr><td>2.&nbsp;</td><td>
<a rel="nofollow" href="https://direct.example.org/page" class='result-link'>Direct Link Result</a>
</td></tr>
<tr><td class='result-snippet'>Another snippet.</td></tr>
</table></body></html>`

func TestParseDDGLiteUnwrapsRedirects(t *testing.T) {
	results := parseDDGLite(ddgFixture)
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(results), results)
	}
	if results[0].URL != "https://www.example.com/guide" {
		t.Errorf("redirect not unwrapped: %q", results[0].URL)
	}
	if results[0].Title != "Example Guide" {
		t.Errorf("title = %q", results[0].Title)
	}
	if !strings.Contains(results[0].Snippet, "examples") {
		t.Errorf("snippet = %q", results[0].Snippet)
	}
	if results[1].URL != "https://direct.example.org/page" {
		t.Errorf("direct link mangled: %q", results[1].URL)
	}
}

func TestDecodeDDGHref(t *testing.T) {
	got := decodeDDGHref("//duckduckgo.com/l/?uddg=https%3A%2F%2Fa.io%2Fx&amp;rut=z")
	if got != "https://a.io/x" {
		t.Errorf("got %q", got)
	}
	if decodeDDGHref("https://plain.example/p") != "https://plain.example/p" {
		t.Error("plain URLs should pass through")
	}
	if decodeDDGHref("//duckduckgo.com/yield.js?q=1") != "" {
		t.Error("non-uddg ddg redirect should be dropped")
	}
}

func TestNewNilWhenDisabled(t *testing.T) {
	if New(Config{Enabled: false}) != nil {
		t.Error("disabled config must yield nil client (tool not available)")
	}
	if New(Config{Enabled: true}) == nil {
		t.Error("enabled config must yield a client")
	}
}

func TestDuckDuckGoSearchViaHttptest(t *testing.T) {
	c := New(Config{Enabled: true})
	ddg := duckduckgo{http: c.providerHTTP}
	// Point the provider at the test server by rewriting its base via client swap:
	// duckduckgo builds the URL from the constant host, so instead we test parsing
	// through the searcher interface with a stub transport.
	ddg.http.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		resp := httptest.NewRecorder()
		resp.WriteString(ddgFixture)
		return resp.Result(), nil
	})
	results, err := ddg.Search(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Error("no results parsed")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Regression (audit H2): the hardened client must refuse requests whose
// dial target or redirect hop lands on an internal address — covering both
// direct SSRF and the redirect/rebinding paths.
func TestHardenedClientBlocksInternalTargets(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SECRET-FROM-LOOPBACK"))
	}))
	defer inner.Close()

	client := newHardenedHTTP()

	// Direct: loopback dial must be refused by the guard.
	_, _, err := get(context.Background(), client, inner.URL)
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("dial guard did not block loopback: %v", err)
	}

	// Redirect hook: link-local metadata endpoint must be refused.
	u, _ := url.Parse("http://169.254.169.254/latest/meta-data/")
	hookErr := client.CheckRedirect(&http.Request{URL: u}, []*http.Request{{URL: u}})
	if hookErr == nil || !strings.Contains(hookErr.Error(), "blocked") {
		t.Fatalf("redirect validator allowed link-local target: %v", hookErr)
	}

	// Redirect hook: public hosts stay allowed.
	pub, _ := url.Parse("https://example.com/x")
	if err := client.CheckRedirect(&http.Request{URL: pub}, []*http.Request{{URL: pub}}); err != nil {
		t.Fatalf("public redirect target wrongly blocked: %v", err)
	}
}

func TestSearXNGJSONParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"title":"T","url":"https://x.io","content":"C"},{"title":"skip me"}]}`))
	}))
	defer srv.Close()

	c := New(Config{Enabled: true, Provider: "searxng", SearXNGURL: srv.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := c.Search.Search(ctx, "q")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Title != "T" || results[0].Snippet != "C" {
		t.Errorf("searxng parse wrong: %+v", results)
	}
}

func TestFetchPageBlocksLocalAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := New(Config{Enabled: true})
	for _, bad := range []string{"http://127.0.0.1/x", "http://localhost/x", "http://10.0.0.1/x", "http://192.168.1.4/x"} {
		if _, _, err := c.FetchPage(context.Background(), bad, 1000); err == nil ||
			!strings.Contains(err.Error(), "blocked") {
			t.Errorf("local address %s not blocked (err=%v)", bad, err)
		}
	}
	// The httptest server itself is on 127.0.0.1 — also blocked. That's correct
	// behavior for the AI-facing fetcher; verified by the loop above.
}

func TestExtractTextStripsScriptsAndTags(t *testing.T) {
	page := `<html><head><style>body{color:red}</style><script>var x = "<b>not text</b>";</script></head>` +
		`<body><h1>Title &amp; More</h1><p>Body text here.</p></body></html>`
	out := ExtractText(page)
	if strings.Contains(out, "color:red") || strings.Contains(out, "var x") || strings.Contains(out, "<b>") {
		t.Errorf("script/style leaked into text: %q", out)
	}
	want := "Title & More Body text here."
	if out != want {
		t.Errorf("text = %q, want %q", out, want)
	}
}

func TestIsLocalHost(t *testing.T) {
	local := []string{"localhost", "127.0.0.1", "10.1.2.3", "192.168.0.15", "172.20.1.1", "169.254.9.9", "0.0.0.0", "nas.local"}
	public := []string{"example.com", "8.8.8.8", "93.184.216.34", "172.32.0.1"}
	for _, h := range local {
		if !isLocalHost(h) {
			t.Errorf("%s should be local", h)
		}
	}
	for _, h := range public {
		if isLocalHost(h) {
			t.Errorf("%s should not be local", h)
		}
	}
}
