package textutil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 4, "hell"},
		{"", 3, ""},
		{"héllo wörld", 5, "héllo"}, // é is one rune
		{"日本語のテキスト", 3, "日本語"},
		{"abc", 0, ""},
	}
	for _, tc := range cases {
		if got := Truncate(tc.in, tc.max); got != tc.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
	// Never split a multi-byte rune: result must stay valid UTF-8.
	s := strings.Repeat("日", 10)
	if out := Truncate(s, 7); !utf8.ValidString(out) {
		t.Error("truncated output is not valid UTF-8")
	}
	if n := len([]rune(Truncate(s, 7))); n != 7 {
		t.Errorf("rune count = %d, want 7", n)
	}
}
