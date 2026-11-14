package login

import (
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	th := NewThrottle()
	th.now = func() time.Time { return now }
	begin := func(want time.Duration, keys ...string) {
		t.Helper()
		got, ok := th.Begin(keys...)
		if !ok || got != want {
			t.Fatalf("Begin(%v) = %v, %v; want %v, true", keys, got, ok, want)
		}
	}

	// Free attempts, then each waits twice as long as the last. The
	// attempts are made at once (no time passes): they queue.
	for i := 0; i < freeFails+1; i++ {
		begin(0, "a")
	}
	begin(1*time.Second, "a")
	begin(3*time.Second, "a") // 1s, then 2s more
	begin(7*time.Second, "a") // then 4s more

	// Keys are independent; a combined attempt waits for the slowest.
	begin(0, "b")
	begin(7*time.Second+8*time.Second, "a", "b")

	// Refused past maxWait, and a refusal is not counted.
	before := *th.recs["a"]
	if _, ok := th.Begin("a"); ok {
		t.Fatal("a wait of more than maxWait was not refused")
	}
	if *th.recs["a"] != before {
		t.Fatal("a refused attempt was counted")
	}

	// Refund undoes a count; Clear forgets a key.
	th.recs["c"] = &record{n: 2, last: now}
	th.Refund("c")
	if th.recs["c"].n != 1 {
		t.Fatalf("after Refund n = %d, want 1", th.recs["c"].n)
	}
	th.Clear("a")
	begin(0, "a")

	// A window later, the slate is clean.
	for i := 0; i < 10; i++ {
		th.Begin("d")
	}
	now = now.Add(window + maxDelay + time.Hour)
	begin(0, "d")
	if n := th.recs["d"].n; n != 1 {
		t.Fatalf("after a window, n = %d, want a fresh count of 1", n)
	}
}

func TestThrottleMemoryIsBounded(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	th := NewThrottle()
	th.now = func() time.Time { return now }
	for i := 0; i < maxRecords+100; i++ {
		now = now.Add(time.Millisecond)
		th.Begin(string(rune('a'+i%26)) + time.Duration(i).String())
	}
	if len(th.recs) > maxRecords {
		t.Fatalf("%d records, want at most %d", len(th.recs), maxRecords)
	}
}
