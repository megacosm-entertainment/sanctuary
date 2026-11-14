package proxy

import (
	"testing"
	"time"
)

func TestRateLimiterSlidingWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRateLimiter(2, time.Minute)
	r.now = func() time.Time { return now }
	if !r.allow("a") || !r.allow("a") {
		t.Fatal("first two attempts refused")
	}
	if r.allow("a") {
		t.Fatal("third attempt within the window allowed")
	}
	if !r.allow("b") {
		t.Fatal("another source was limited by a's attempts")
	}
	now = now.Add(time.Minute + time.Second)
	if !r.allow("a") {
		t.Fatal("attempt after the window refused")
	}
}
