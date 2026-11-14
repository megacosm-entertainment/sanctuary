package login

import (
	"sync"
	"time"
)

// Throttle slows password guessing, per account name and per source, so
// guessing over many connections is no faster than over one.
//
// Every attempt is counted when it begins, as if it will fail, and a
// success refunds it. Counting up front is what makes parallel attempts
// queue: each one reserves the next slot, so a hundred connections trying
// at once wait their turns instead of all guessing in the same instant.
//
// The first freeFails attempts in a window are free; after that each one
// waits twice as long as the last (1s, 2s, 4s, ... up to maxDelay). A wait
// longer than maxWait is refused rather than queued, so an attacker can
// delay an account's logins by minutes, not lock it for days.
//
// It is in memory: a gateway restart forgets it.
type Throttle struct {
	mu   sync.Mutex
	recs map[string]*record
	now  func() time.Time
}

type record struct {
	n    int       // attempts counted in this window
	last time.Time // last attempt's slot
	next time.Time // earliest slot for the next attempt
}

const (
	freeFails  = 3
	window     = 15 * time.Minute
	maxDelay   = 5 * time.Minute
	maxWait    = 30 * time.Second
	maxRecords = 8192 // bounded memory; see prune
)

// NewThrottle returns an empty throttle, shared by every session.
func NewThrottle() *Throttle {
	return &Throttle{recs: map[string]*record{}, now: time.Now}
}

func delay(over int) time.Duration {
	d := time.Duration(1) << min(over-1, 20) * time.Second
	return min(d, maxDelay)
}

// Begin counts an attempt against every key and returns how long the
// caller must wait before making it. ok is false when that wait would be
// longer than maxWait: the attempt is then not counted, and the caller
// should refuse it.
func (t *Throttle) Begin(keys ...string) (wait time.Duration, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	recs := make([]*record, len(keys))
	at := now
	for i, k := range keys {
		r := t.recs[k]
		if r != nil && now.Sub(r.last) > window {
			r = nil // stale: start a new window
		}
		if r == nil {
			if len(t.recs) >= maxRecords {
				t.prune(now)
			}
			r = &record{}
			t.recs[k] = r
		}
		recs[i] = r
		if r.next.After(at) {
			at = r.next
		}
	}
	if at.Sub(now) > maxWait {
		return 0, false
	}
	for _, r := range recs {
		r.n++
		r.last = at
		if r.n > freeFails {
			r.next = at.Add(delay(r.n - freeFails))
		}
	}
	return at.Sub(now), true
}

// Refund undoes one counted attempt for each key: a login that succeeded.
func (t *Throttle) Refund(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		if r := t.recs[k]; r != nil && r.n > 0 {
			r.n--
		}
	}
}

// Clear forgets key: an account whose owner just proved who they are.
func (t *Throttle) Clear(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.recs, key)
}

// prune drops stale records; if that frees nothing, it drops the record
// least recently used, so memory stays bounded under a flood of names.
func (t *Throttle) prune(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, r := range t.recs {
		if now.Sub(r.last) > window {
			delete(t.recs, k)
			continue
		}
		if oldestKey == "" || r.last.Before(oldest) {
			oldestKey, oldest = k, r.last
		}
	}
	if len(t.recs) >= maxRecords && oldestKey != "" {
		delete(t.recs, oldestKey)
	}
}
