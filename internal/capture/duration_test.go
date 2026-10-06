package capture

import (
	"testing"
	"time"
)

// A raw `time.Duration(secs) * time.Second` wraps negative once secs exceeds
// MaxInt64/1e9, and a negative duration is already expired — the capture
// stops before the first packet, exactly like the zero-duration case but
// silently accepted.
func TestSecondsToDurationDoesNotOverflow(t *testing.T) {
	overflowing := []uint64{9223372037, 10000000000, 18446744073709551615}
	for _, secs := range overflowing {
		if raw := time.Duration(secs) * time.Second; raw > 0 {
			t.Fatalf("fixture %d no longer overflows (got %v)", secs, raw)
		}
		got := SecondsToDuration(secs)
		if got <= 0 {
			t.Errorf("SecondsToDuration(%d) = %v, want a positive duration", secs, got)
		}
		// Callers add a small slack before using the result as a deadline
		// (live-interpret uses "+ 2*time.Second"). Clamping flush against
		// MaxInt64/1e9 made that addition overflow again, so the ceiling has
		// to leave headroom.
		for _, slack := range []time.Duration{2 * time.Second, 30 * time.Minute, time.Hour} {
			if got+slack <= 0 {
				t.Errorf("SecondsToDuration(%d)+%v = %v overflowed to a non-positive deadline",
					secs, slack, got+slack)
			}
		}
	}
	for _, tc := range []struct {
		secs uint64
		want time.Duration
	}{
		{0, 0},
		{1, time.Second},
		{300, 300 * time.Second},
	} {
		if got := SecondsToDuration(tc.secs); got != tc.want {
			t.Errorf("SecondsToDuration(%d) = %v, want %v", tc.secs, got, tc.want)
		}
	}
}
