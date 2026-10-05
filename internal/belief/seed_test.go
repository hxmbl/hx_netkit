package belief

import (
	"sync"
	"testing"

	"github.com/hxmbl/hx_netkit/internal/intel"
)

// Correlate() emits several findings per IP, strongest first. The strongest
// one must seed the belief: a 90% DATA_EXFIL verdict must not be overwritten
// by the 40% SERVER finding that came after it.
func TestStrongestFindingSeedsBelief(t *testing.T) {
	s := New()
	s.InitializeFromFindings([]intel.Finding{
		{IP: "192.168.1.5", Kind: intel.KDataExfil, Confidence: 0.9},
		{IP: "192.168.1.5", Kind: intel.KServer, Confidence: 0.4},
	})
	b, ok := s.Get("192.168.1.5")
	if !ok {
		t.Fatal("IP not tracked")
	}
	if b.MaxCat != Bot {
		t.Errorf("MaxCat = %v, want BOT (from the 90%% DATA_EXFIL finding); dist=%v", b.MaxCat, b.Dist)
	}
}

// The opposite order must give the same answer — the result may not depend on
// how the findings were sorted.
func TestStrongestFindingWinsRegardlessOfOrder(t *testing.T) {
	s := New()
	s.InitializeFromFindings([]intel.Finding{
		{IP: "192.168.1.5", Kind: intel.KServer, Confidence: 0.4},
		{IP: "192.168.1.5", Kind: intel.KDataExfil, Confidence: 0.9},
	})
	b, _ := s.Get("192.168.1.5")
	if b.MaxCat != Bot {
		t.Errorf("MaxCat = %v, want BOT; dist=%v", b.MaxCat, b.Dist)
	}
}

// The background scanner goroutine folds nmap evidence in while the chat loop
// reads beliefs (/beliefs, threats tool) and adds new ones (scan_ip). Run with
// -race; an unguarded System aborts the process on concurrent map access.
func TestConcurrentScannerAndChatAccess(t *testing.T) {
	s := New()
	for i := 0; i < 40; i++ {
		s.Ensure(testIP(i))
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // background scanner
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if ip, _, ok := s.PriorityIP(3); ok {
				s.UpdateFromNmap(ip, i%2 == 0, []uint32{22, 443, 9100})
			}
		}
	}()
	go func() { // chat loop: /beliefs + threats tool
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = s.FormatAll()
			_, _ = s.FormatIP(testIP(i % 40))
			s.Ensure(testIP(100 + i%20))
		}
	}()
	wg.Wait()

	if s.Len() == 0 {
		t.Error("beliefs lost after concurrent access")
	}
}

func testIP(i int) string {
	if i < 10 {
		return "192.168.1." + string(rune('0'+i))
	}
	return "192.168.1." + itoaBelief(i)
}

func itoaBelief(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoaBelief(i/10) + string(rune('0'+i%10))
}
