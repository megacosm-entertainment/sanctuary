package realm

import (
	"testing"
	"time"
)

// The schedule from protocol.md §8: each wait is jittered within a ceiling
// that doubles from Min and stops at Max.
func TestBackoffDelayBounds(t *testing.T) {
	b := Backoff{Min: time.Second, Max: 60 * time.Second}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for n, ceil := range want {
		ceil *= time.Second
		var max time.Duration
		for i := 0; i < 2000; i++ {
			d := b.delay(n)
			if d < 0 || d > ceil {
				t.Fatalf("delay(%d) = %v, want within [0, %v]", n, d, ceil)
			}
			max = max2(max, d)
		}
		// Full jitter: over 2000 draws the largest should come near the
		// ceiling; a schedule stuck at Min would not.
		if max < ceil/2 {
			t.Fatalf("delay(%d) never exceeded %v in 2000 draws; ceiling is %v", n, max, ceil)
		}
	}
	if d := b.delay(1000); d > b.Max {
		t.Fatalf("delay(1000) = %v, want capped at %v (no overflow)", d, b.Max)
	}
}

func max2(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
