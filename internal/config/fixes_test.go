package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression (audit H1): numeric ordering — capture_100 is newer than
// capture_99 even though "99" > "100" lexicographically.
func TestLatestDBNumericOrdering(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(CapturesDir(), 0o755)

	for _, name := range []string{"capture_99.db", "capture_100.db", "capture_1787686900123456789.db"} {
		os.WriteFile(filepath.Join(CapturesDir(), name), []byte{}, 0o600)
	}
	got, err := LatestDB()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "capture_1787686900123456789.db" {
		t.Errorf("latest = %q, want the numerically largest capture", filepath.Base(got))
	}
}

func TestCaptureNameLess(t *testing.T) {
	if !CaptureNameLess("capture_99.db", "capture_100.db") {
		t.Error("99 should sort before 100")
	}
	if CaptureNameLess("capture_100.db", "capture_99.db") {
		t.Error("comparator not antisymmetric")
	}
	if !CaptureNameLess("notes.txt", "capture_1.db") {
		t.Error("non-capture names fall back to lexicographic")
	}
	if CaptureNameLess("capture_5.db", "capture_5.db") {
		t.Error("equal names must compare equal")
	}
}
