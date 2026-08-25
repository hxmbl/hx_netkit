package nlsearch

import (
	"strings"
	"testing"
)

// Regression (audit L20): user input containing LIKE wildcards is matched
// literally instead of broadening the pattern.
func TestLikeWildcardsAreEscaped(t *testing.T) {
	db := testDB(t)

	// Insert a domain containing literal wildcard characters.
	if _, err := db.Exec(`INSERT INTO packets (epoch, ip_src, ip_dst, dns_query) VALUES
		(2000, '10.9.9.9', '10.0.0.1', 'weird_100%.example')`); err != nil {
		t.Fatal(err)
	}

	out := Execute(db, "dns weird_100")
	if !strings.Contains(out, "weird_100%.example") {
		t.Errorf("literal wildcard chars not matched literally:\n%s", out)
	}

	// The unescaped form would match everything; escaped, a bare '_' query
	// only matches domains containing a real underscore.
	out = Execute(db, "ip 10.9.9.9")
	if !strings.Contains(out, "weird_100%.example") && !strings.Contains(out, "(no traffic found)") {
		t.Errorf("unexpected rendering:\n%s", out)
	}
}
