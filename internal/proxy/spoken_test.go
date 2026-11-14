package proxy

import (
	"testing"
	"time"
)

func TestSpoken(t *testing.T) {
	for d, want := range map[time.Duration]string{
		2 * time.Minute:         "2 minutes",
		time.Minute:             "1 minute",
		90 * time.Second:        "2 minutes", // rounded: a screen reader user wants one number
		45 * time.Second:        "45 seconds",
		1200 * time.Millisecond: "1 second",
		100 * time.Millisecond:  "1 second", // never "0 seconds"
	} {
		if got := spoken(d); got != want {
			t.Errorf("spoken(%v) = %q, want %q", d, got, want)
		}
	}
}
