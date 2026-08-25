package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression (audit M1): two captures in the same second must not share a path.
func TestCapturePathNoCollision(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a := CapturePath(false, "")
	b := CapturePath(false, "")
	if a == b {
		t.Fatalf("collision: %s", a)
	}
}

// Regression (audit M2): epoch 0 is stored as 0.0, not NULL.
func TestZeroEpochStoredAsZero(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InsertPacket(0, "10.0.0.1", "10.0.0.2", 1234, 80, 0, 0, "", "", 100); err != nil {
		t.Fatal(err)
	}
	var epoch float64
	if err := db.QueryRow(`SELECT epoch FROM packets WHERE ip_src = '10.0.0.1'`).Scan(&epoch); err != nil {
		t.Fatalf("epoch not readable as plain float64: %v", err)
	}
	if epoch != 0 {
		t.Errorf("epoch = %v", epoch)
	}
}

// Regression (audit M5): DNS attribution deterministically reports the
// dominant requester per domain.
func TestDNSQueriesDominantRequester(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 9; i++ {
		_ = db.InsertPacket(float64(i), "10.0.0.1", "1.1.1.1", 0, 53, 50000, 53, "evil.example", "", 80)
	}
	_ = db.InsertPacket(99, "10.9.9.9", "1.1.1.1", 0, 53, 50001, 53, "evil.example", "", 80)

	rows, err := db.DNSQueries()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	if rows[0].Src != "10.0.0.1" || rows[0].Count != 9 {
		t.Errorf("dominant requester wrong: %+v", rows[0])
	}
}

// Regression (audit M8): OpenExisting rejects non-SQLite and foreign databases.
func TestOpenExistingValidation(t *testing.T) {
	dir := t.TempDir()

	junk := filepath.Join(dir, "junk.db")
	os.WriteFile(junk, []byte("this is definitely not sqlite"), 0o600)
	if _, err := OpenExisting(junk); err == nil {
		t.Error("garbage file accepted")
	}

	// A real SQLite file with an unrelated schema must be rejected clearly.
	foreign := filepath.Join(dir, "foreign.db")
	raw, err := sql.Open("sqlite", foreign)
	if err != nil {
		t.Skipf("cannot create foreign db: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE unrelated (x INTEGER)`); err != nil {
		t.Skipf("cannot populate foreign db: %v", err)
	}
	raw.Close()

	_, err = OpenExisting(foreign)
	if err == nil || !strings.Contains(err.Error(), "not a correlator capture") {
		t.Errorf("foreign schema should be rejected clearly, got: %v", err)
	}
}

// Regression (audit M9): filenames with URI metacharacters survive a
// close/reopen round trip.
func TestDSNHandlesWeirdFilenames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weird name?100%.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.InsertPacket(1.5, "10.0.0.3", "10.0.0.4", 1, 2, 0, 0, "", "", 60); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	db2, err := OpenExisting(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	s, err := db2.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.Packets != 1 {
		t.Errorf("packets after reopen = %d, want 1", s.Packets)
	}
}
