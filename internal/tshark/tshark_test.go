package tshark

import (
	"strings"
	"testing"
)

const nestedLine = `{"timestamp":"1700000000","_source":{"layers":{"frame_time_epoch":["1700000001.234"],"frame_len":["1500"],"ip_src":["192.168.1.10"],"ip_dst":["93.184.216.34"],"tcp_srcport":["49152"],"tcp_dstport":["443"]}}}`

const flatLine = `{"layers":{"frame.time_epoch":"1700000002.5","frame.len":"64","ip.src":"10.0.0.2","ip.dst":"10.0.0.1","udp.srcport":"5353","udp.dstport":"5353","dns.qry.name":"_airplay._tcp.local"}}`

const arrayFlatLine = `{"layers":{"frame.time_epoch":["1700000003"],"ip.src":["8.8.8.8"],"ip.dst":["192.168.1.10"],"udp.srcport":["53"],"dns.qry.name":["example.com","alt.example.com"]}}`

const indexLine = `{"index":{"segments":12},"segments":12}`

func TestParseNestedEkLine(t *testing.T) {
	p, ok := ParseLine(nestedLine)
	if !ok {
		t.Fatal("nested line should parse")
	}
	if p.Epoch != 1700000001.234 || !p.HasEpoch {
		t.Errorf("epoch = %v has=%v", p.Epoch, p.HasEpoch)
	}
	if p.FrameLen != 1500 {
		t.Errorf("frame_len = %d", p.FrameLen)
	}
	if p.IPSrc != "192.168.1.10" || p.IPDst != "93.184.216.34" {
		t.Errorf("ips = %q -> %q", p.IPSrc, p.IPDst)
	}
	if p.TCPsrc != 49152 || p.TCPdst != 443 {
		t.Errorf("ports tcp %d/%d", p.TCPsrc, p.TCPdst)
	}
	if p.DNSQuery != "" {
		t.Errorf("unexpected dns %q", p.DNSQuery)
	}
}

func TestParseFlatEkLine(t *testing.T) {
	p, ok := ParseLine(flatLine)
	if !ok {
		t.Fatal("flat line should parse")
	}
	if p.Epoch != 1700000002.5 {
		t.Errorf("epoch = %v", p.Epoch)
	}
	if p.UDPsrc != 5353 || p.UDPdst != 5353 {
		t.Errorf("ports udp %d/%d", p.UDPsrc, p.UDPdst)
	}
	if p.DNSQuery != "_airplay._tcp.local" {
		t.Errorf("dns = %q", p.DNSQuery)
	}
}

func TestParseArrayValuesTakeFirst(t *testing.T) {
	p, ok := ParseLine(arrayFlatLine)
	if !ok {
		t.Fatal("array line should parse")
	}
	if p.DNSQuery != "example.com" {
		t.Errorf("dns = %q, want first element", p.DNSQuery)
	}
	if p.Epoch != 1700000003 {
		t.Errorf("epoch = %v", p.Epoch)
	}
}

func TestSkippableLines(t *testing.T) {
	if _, ok := ParseLine(indexLine); ok {
		t.Error("index line should not produce a packet")
	}
	if !Skippable(indexLine) {
		t.Error("index line should be skippable")
	}
	if !Skippable("   \n") {
		t.Error("blank should be skippable")
	}
	if !Skippable(`{"index":1}`) || Skippable(nestedLine) {
		t.Error("Skippable misclassification")
	}
}

func TestParseGarbage(t *testing.T) {
	for _, bad := range []string{"", "not json", "{}", "[]", `{"layers":"nope"}`} {
		if _, ok := ParseLine(bad); ok {
			t.Errorf("%q should fail to parse", bad)
		}
	}
}

func TestArgsDefaultFilter(t *testing.T) {
	got := Args("en1", "")
	want := "-i en1 -n -l -T ek -f not host 127.0.0.1"
	if got[0] != "-i" || got[1] != "en1" {
		t.Fatalf("interface args wrong: %v", got)
	}
	if joined := strings.Join(got[:8], " "); joined != want {
		t.Errorf("prefix = %q, want %q", joined, want)
	}
	found := map[string]bool{}
	for i, a := range got {
		if a == "-e" && i+1 < len(got) {
			found[got[i+1]] = true
		}
	}
	for _, f := range fields {
		if !found[f] {
			t.Errorf("missing -e field %s", f)
		}
	}
}

func TestArgsCustomFilter(t *testing.T) {
	got := Args("eth0", "tcp port 443")
	if !strings.Contains(strings.Join(got, " "), "-f tcp port 443") {
		t.Errorf("custom filter lost: %v", got)
	}
}
