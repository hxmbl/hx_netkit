// Package textutil holds small text helpers shared across packages.
package textutil

import "unicode/utf8"

// Truncate cuts s to at most maxRunes runes without splitting a multi-byte
// character. A trailing ellipsis is NOT added, so output length stays
// predictable for prompts and table cells.
func Truncate(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes])
}
