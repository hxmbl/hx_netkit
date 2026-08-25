package tools

import (
	"testing"
)

// Regression (audit M3): keyword guard uses word boundaries + literal
// stripping, so identifiers and quoted text no longer trip it.
func TestSafeSQLWordBoundaries(t *testing.T) {
	good := []string{
		"SELECT created_at, updated_at FROM packets",
		"SELECT * FROM devices WHERE notes LIKE '%printed%'",
		"SELECT 'drop table packets' AS warning",
		`SELECT "delete_me" FROM t`,
		"SELECT points_into FROM geometry",
		"WITH recent AS (SELECT * FROM packets) SELECT * FROM recent",
		// comments must not trip keyword guards (pass-2 regression)
		"SELECT 1 /* DROP TABLE packets */",
		"SELECT epoch -- DELETE later\nFROM packets",
	}
	bad := []string{
		"DROP TABLE packets",
		"DELETE FROM packets WHERE id = 1",
		"UPDATE devices SET hostname = 'x'",
		"INSERT INTO packets VALUES (1)",
		"ATTACH DATABASE '/etc/passwd' AS pwn",
		"PRAGMA journal_mode=DELETE",
		"VACUUM",
		"SELECT 1; DROP TABLE packets",
		"REPLACE INTO devices VALUES ('x')",
	}
	for _, q := range good {
		if err := SafeSQL(q); err != nil {
			t.Errorf("legitimate query rejected: %q → %v", q, err)
		}
	}
	for _, q := range bad {
		if err := SafeSQL(q); err == nil {
			t.Errorf("dangerous query accepted: %q", q)
		}
	}
}

// Regression (audit M4): explicit zeros mean default, not minimum.
func TestResolveCountDefaults(t *testing.T) {
	cases := []struct {
		args map[string]any
		def  int64
		want int64
	}{
		{map[string]any{}, 10, 10},                         // absent → default
		{map[string]any{"duration": float64(0)}, 10, 10},   // explicit zero → default
		{map[string]any{"duration": float64(-5)}, 10, 10},  // negative → default
		{map[string]any{"duration": float64(30)}, 10, 30},  // honored
		{map[string]any{"duration": float64(999)}, 10, 60}, // clamped to hi
		{map[string]any{"limit": float64(0)}, 20, 20},      // zero limit → default 20
	}
	for _, tc := range cases {
		key := "duration"
		if _, ok := tc.args["limit"]; ok {
			key = "limit"
		}
		var lo, hi int64 = 1, 60
		if key == "limit" {
			hi = 200
		}
		if got := resolveCount(tc.args, key, tc.def, lo, hi); got != tc.want {
			t.Errorf("resolveCount(%v, %q, def=%d) = %d, want %d", tc.args, key, tc.def, got, tc.want)
		}
	}
}
