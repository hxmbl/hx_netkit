package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSchemaAndPacketInsert(t *testing.T) {
	db := openTestDB(t)

	if err := db.InsertPacket(1000.5, "192.168.1.1", "93.184.216.34", 49200, 443, 0, 0, "", "{}", 1500); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertPacket(1001, "192.168.1.2", "192.168.1.1", 0, 0, 5353, 5353, "example.com", "", 90); err != nil {
		t.Fatal(err)
	}

	s, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.Packets != 2 || s.DNSDomains != 1 || s.Devices != 0 {
		t.Errorf("stats wrong: %+v", s)
	}

	var dns string
	if err := db.QueryRow(`SELECT dns_query FROM packets WHERE epoch = 1001`).Scan(&dns); err != nil {
		t.Fatal(err)
	}
	if dns != "example.com" {
		t.Errorf("dns = %q", dns)
	}
	var src any
	if err := db.QueryRow(`SELECT ip_src FROM packets WHERE epoch = 1000.5`).Scan(&src); err != nil {
		t.Fatal(err)
	}
}

func TestUpsertDeviceCoalesce(t *testing.T) {
	db := openTestDB(t)

	if err := db.UpsertDevice("10.0.0.5", "AA:BB", "host-a", "VendorX", "Linux", "22/open/ssh", 100); err != nil {
		t.Fatal(err)
	}
	// Second update with empty fields must not clobber existing values.
	if err := db.UpsertDevice("10.0.0.5", "", "", "", "", "", 200); err != nil {
		t.Fatal(err)
	}
	devices, err := db.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d", len(devices))
	}
	d := devices[0]
	if d.Hostname == nil || *d.Hostname != "host-a" {
		t.Errorf("hostname clobbered: %+v", d.Hostname)
	}
	if d.MAC == nil || *d.MAC != "AA:BB" {
		t.Error("mac clobbered")
	}
	if d.Ports != "22/open/ssh" {
		t.Errorf("ports clobbered: %q", d.Ports)
	}

	// Non-empty new values win.
	if err := db.UpsertDevice("10.0.0.5", "", "renamed", "", "Windows", "3389/open/ms-wbt", 300); err != nil {
		t.Fatal(err)
	}
	devices, _ = db.Devices()
	if *devices[0].Hostname != "renamed" || devices[0].Ports != "3389/open/ms-wbt" {
		t.Errorf("update failed: %+v", devices[0])
	}
}

func TestRecordScanAndSummaries(t *testing.T) {
	db := openTestDB(t)
	_ = db.RecordScan("192.168.1.0/24", "<xml/>", "host one\nhost two", 1)
	_ = db.RecordScan("10.0.0.0/8", "<xml/>", "", 2)

	sums, err := db.NmapSummaries()
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 1 || !strings.Contains(sums[0], "host two") {
		t.Errorf("summaries = %#v; empty summaries must be skipped", sums)
	}
}

func TestTopTalkersAndDNS(t *testing.T) {
	db := openTestDB(t)
	for i := 0; i < 5; i++ {
		_ = db.InsertPacket(float64(i), "10.0.0.1", "10.0.0.9", 0, 80, 0, 0, "", "", 60)
	}
	for i := 0; i < 2; i++ {
		_ = db.InsertPacket(float64(i), "10.0.0.2", "10.0.0.9", 0, 443, 0, 0, "a.example.com", "", 60)
	}
	_ = db.InsertPacket(9, "10.0.0.2", "10.0.0.9", 0, 443, 0, 0, "b.example.com", "", 60)

	talkers, err := db.TopTalkers(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(talkers) != 1 || talkers[0].IP != "10.0.0.1" || talkers[0].Count != 5 {
		t.Errorf("talkers wrong: %+v", talkers)
	}

	dnsRows, err := db.DNSQueries()
	if err != nil {
		t.Fatal(err)
	}
	if len(dnsRows) != 2 || dnsRows[0].Query != "a.example.com" {
		t.Errorf("dns rows wrong: %+v", dnsRows)
	}
}

func TestQueryRowsRendersValues(t *testing.T) {
	db := openTestDB(t)
	_ = db.InsertPacket(1, "10.0.0.1", "10.0.0.2", 1024, 443, 0, 0, "", "", 500)

	cols, rows, err := db.QueryRows(`SELECT ip_src, ip_dst, tcp_dst_port FROM packets ORDER BY epoch`, 10)
	if err != nil {
		t.Fatal(err)
	}
	wantCols := "ip_src|ip_dst|tcp_dst_port"
	gotCols := strings.Join(cols, "|")
	if gotCols != wantCols {
		t.Errorf("cols = %q", gotCols)
	}
	if len(rows) != 1 || rows[0][0] != "10.0.0.1" || rows[0][1] != "10.0.0.2" || rows[0][2] != "443" {
		t.Errorf("rows = %#v", rows)
	}
}

func TestCapturePathNaming(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // never touch the developer's real ~/.correlator
	path := CapturePath(true, "")
	if !strings.HasPrefix(filepath.Base(path), "correlator_") {
		t.Errorf("no-save name wrong: %q", path)
	}
	saved := CapturePath(false, "")
	if !strings.Contains(saved, ".correlator") {
		t.Errorf("saved path unexpected: %q", saved)
	}
	if fixed := CapturePath(false, "/tmp/x.db"); fixed != "/tmp/x.db" {
		t.Errorf("explicit output ignored: %q", fixed)
	}
}

func TestOpenExistingFailsWhenMissing(t *testing.T) {
	if _, err := OpenExisting("/nonexistent/path.db"); err == nil {
		t.Fatal("expected error opening missing database")
	}
}
