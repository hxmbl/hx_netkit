package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hxmbl/hx_netkit/internal/intel"
)

func sampleFindings() []intel.Finding {
	return []intel.Finding{
		{IP: "10.0.0.1", Kind: intel.KScanner, Confidence: 0.78, Detail: "port sweep", Indicators: []string{"40 ports", "sequential"}},
		{IP: "10.0.0.2", Kind: intel.KC2Beacon, Confidence: 0.91, Detail: "regular beacon"},
		{IP: "10.0.0.3", Kind: intel.KServer, Confidence: 0.66, Detail: "many clients"},
		{IP: "10.0.0.4", Kind: intel.KBrowser, Confidence: 0.55, Detail: "web browsing"},
	}
}

func TestRenderFindingsFiltersAndOrders(t *testing.T) {
	var b bytes.Buffer
	RenderFindings(&b, sampleFindings(), FindingsOptions{
		Color:      false,
		KindFilter: "threat",
	})
	out := b.String()
	if strings.Contains(out, "BROWSER") || strings.Contains(out, "SERVER") {
		t.Errorf("benign kinds leaked through threat filter:\n%s", out)
	}
	if !strings.Contains(out, "SCANNER") || !strings.Contains(out, "C2_BEACON") {
		t.Errorf("expected threats present:\n%s", out)
	}
	// Critical group must come before warning groups.
	if strings.Index(out, "C2_BEACON") > strings.Index(out, "SCANNER") {
		t.Errorf("critical group not rendered first:\n%s", out)
	}
}

func TestRenderFindingsMinConfidenceAndTopN(t *testing.T) {
	var b bytes.Buffer
	RenderFindings(&b, sampleFindings(), FindingsOptions{MinConfidencePc: 60, TopN: 2})
	out := b.String()
	if strings.Contains(out, "BROWSER") { // 55% < 60
		t.Error("low-confidence finding survived filter")
	}
	for _, want := range []string{"10.0.0.1", "10.0.0.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected top-N finding %s in:\n%s", want, out)
		}
	}
	for _, gone := range []string{"10.0.0.3", "10.0.0.4"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s should have been cut by TopN:\n%s", gone, out)
		}
	}
}

func TestRenderFindingsKindNamesAndEmpty(t *testing.T) {
	var b bytes.Buffer
	RenderFindings(&b, sampleFindings(), FindingsOptions{KindFilter: "server,browser"})
	if !strings.Contains(b.String(), "SERVER") || !strings.Contains(b.String(), "BROWSER") {
		t.Errorf("explicit kind list failed:\n%s", b.String())
	}

	b.Reset()
	RenderFindings(&b, nil, FindingsOptions{})
	if !strings.Contains(b.String(), "(no findings match)") && !strings.Contains(b.String(), "(no findings)") {
		t.Errorf("empty rendering = %q", b.String())
	}
}

func TestParseKindFilter(t *testing.T) {
	for _, ok := range []string{"", "all", "threat", "benign", "scanner,c2_beacon", "TOR"} {
		if _, err := ParseKindFilter(ok); err != nil {
			t.Errorf("ParseKindFilter(%q) = %v, want ok", ok, err)
		}
	}
	if _, err := ParseKindFilter("nope"); err == nil {
		t.Error("invalid kind accepted")
	}
}

func TestBar(t *testing.T) {
	if got := Bar(0.84, false); got != "████████░░" {
		t.Errorf("Bar(0.84) = %q", got)
	}
	if got := Bar(1.5, false); got != "██████████" {
		t.Errorf("Bar(1.5) overflow = %q", got)
	}
	if got := Bar(0, false); got != "░░░░░░░░░░" {
		t.Errorf("Bar(0) = %q", got)
	}
	colored := Bar(0.5, true)
	if colored == Bar(0.5, false) {
		t.Log("color profile is plain (piped test env) — acceptable")
	}
}

func TestProgressThrottleAndFormat(t *testing.T) {
	var b bytes.Buffer
	p := NewProgress(&b, "[cap]", 300*time.Second)

	if p.MaybeRender(100, 1024) {
		t.Error("first render must be throttled to interval start") // last==start → immediately after New it's allowed? see below
	}
	// After interval passes virtually:
	p.last = p.last.Add(-time.Second)
	if !p.MaybeRender(12345, 8_400_000) {
		t.Error("render expected after throttle window")
	}
	out := b.String()
	for _, want := range []string{"12,345 pkts", "8.0 MB", "pps", "elapsed", "4m59s"} {
		if !strings.Contains(out, want) {
			t.Errorf("progress line missing %q:\n%s", want, out)
		}
	}
	b.Reset()
	p.Finish()
	if strings.ContainsRune(b.String(), '█') || len(b.String()) == 0 {
		t.Logf("finish clears line (got %q)", b.String())
	}
}

func TestStatusString(t *testing.T) {
	if StatusOK.String(false) != "ok" || StatusWarn.String(false) != "warn" || StatusFail.String(false) != "FAIL" {
		t.Error("plain status strings wrong")
	}
}
