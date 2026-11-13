package session

import (
	"context"
	"sync"
)

// Registry tracks live sessions, for counts (MSSP PLAYERS, connection
// limits) and for shutdown.
type Registry struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
	perHost  map[string]int
	reserved int
	wg       sync.WaitGroup
}

func NewRegistry() *Registry {
	return &Registry{sessions: map[uint64]*Session{}, perHost: map[string]int{}}
}

// Count returns the number of live sessions.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// Reserve claims a slot for host if the global and per-host limits allow.
// Call Release(host) if the slot is not then used by Serve.
func (r *Registry) Reserve(host string, maxTotal, maxPerHost int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if maxTotal > 0 && r.reserved >= maxTotal {
		return false
	}
	if maxPerHost > 0 && r.perHost[host] >= maxPerHost {
		return false
	}
	r.perHost[host]++
	r.reserved++
	return true
}

// Release returns a slot claimed by Reserve.
func (r *Registry) Release(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reserved--
	if r.perHost[host]--; r.perHost[host] <= 0 {
		delete(r.perHost, host)
	}
}

// Serve runs h on s, registered for its lifetime, and closes s when h
// returns. host is the key previously passed to Reserve; it is released when
// the session ends. Serve blocks until the session is fully closed.
func (r *Registry) Serve(ctx context.Context, host string, s *Session, h Handler) {
	r.mu.Lock()
	r.sessions[s.ID] = s
	r.mu.Unlock()
	r.wg.Add(1)
	defer func() {
		r.mu.Lock()
		delete(r.sessions, s.ID)
		r.mu.Unlock()
		r.Release(host)
		r.wg.Done()
	}()

	s.log.Info("session opened")
	h.ServeSession(ctx, s)
	s.Close()
	<-s.Done()
	if err := s.Err(); err != nil {
		s.log.Info("session closed", "err", err)
	} else {
		s.log.Info("session closed")
	}
}

// Wait blocks until every session started with Serve has ended.
func (r *Registry) Wait() { r.wg.Wait() }
