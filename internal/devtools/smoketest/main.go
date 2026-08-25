// Command smoketest generates a synthetic capture database for offline
// verification of the analysis pipeline. Dev tool — not part of releases.
//
// Usage: go run ./internal/devtools/smoketest [db-path]
package main

import (
	"fmt"
	"os"

	"github.com/hxmbl/hx_netkit/internal/store"
)

func main() {
	path := "/tmp/hxsmoke/capture.db"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	db, err := store.Open(path)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	for i := 0; i < 40; i++ {
		_ = db.InsertPacket(1000+float64(i), "192.168.1.66", "192.168.1.1", 40000, int64(1000+i), 0, 0, "", "", 60)
	}
	for i := 0; i < 30; i++ {
		_ = db.InsertPacket(1000+float64(i)*2, "192.168.1.50", "93.184.216.34", int64(49000+i), 443, 0, 0, "example.com", "", 1400)
	}
	_ = db.UpsertDevice("192.168.1.1", "AA:BB:CC", "gateway.local", "Ubiquiti", "Linux", "22/open/ssh", 900)
	fmt.Println("generated", path)
}
