package proxy

import (
	"fmt"
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

// RT-3-4: many distinct sources must not make each accept slower, and the
// table must not grow past its cap.
func TestRateLimiterBoundedUnderManySources(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRateLimiter(30, time.Minute)
	r.now = func() time.Time { return now }
	r.max = 1000
	start := time.Now()
	for i := 0; i < 50000; i++ {
		r.allow(fmt.Sprintf("198.51.%d.%d", i/256, i%256))
	}
	if n := len(r.seen); n > r.max {
		t.Fatalf("limiter remembers %d sources, cap %d", n, r.max)
	}
	// Before the fix this was about 10 s at 40,000 sources.
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("50,000 distinct sources took %v", d)
	}
	if r.allow("203.0.113.9") {
		t.Fatal("a new source was allowed while the table is full of recent ones")
	}
	if !r.allow("198.51.0.0") {
		t.Fatal("a known source was refused because the table is full")
	}
	now = now.Add(time.Minute + time.Second) // everything ages out
	if !r.allow("203.0.113.9") {
		t.Fatal("a new source was refused after the old ones aged out")
	}
}

func TestSourceKeyGroupsIPv6By64(t *testing.T) {
	a, b := sourceKey("2001:db8:1:2:aaaa::1"), sourceKey("2001:db8:1:2:ffff::9")
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("sourceKey = %q, %q; want both 2001:db8:1:2::/64", a, b)
	}
	if sourceKey("2001:db8:1:3::1") == a {
		t.Fatal("different /64s share a key")
	}
	if sourceKey("192.0.2.7") != "192.0.2.7" {
		t.Fatal("an IPv4 source was not kept as is")
	}
}
