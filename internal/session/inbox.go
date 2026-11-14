package session

import "sync"

// Inbox reads a session's inbound events on one goroutine, for as long as
// the session lasts, so that stages which take turns with the player
// (login, the lobby, a realm, the lobby again) can each consume events
// without leaving a reader of their own behind. A session is read from one
// goroutine only; the Inbox is that goroutine.
type Inbox struct {
	// Events delivers inbound events in order.
	Events <-chan Inbound
	// Done is closed when the player has gone (the read failed). It stays
	// closed, so every stage that looks sees it, however many have looked
	// before; Err says why.
	Done <-chan struct{}

	mu  sync.Mutex
	err error
}

// NewInbox starts reading s. Create one per session, before any stage
// reads from it.
func NewInbox(s *Session) *Inbox {
	events := make(chan Inbound, 64)
	done := make(chan struct{})
	in := &Inbox{Events: events, Done: done}
	go func() {
		defer close(done)
		for {
			ev, err := s.Recv()
			if err != nil {
				in.mu.Lock()
				in.err = err
				in.mu.Unlock()
				return
			}
			select {
			case events <- ev:
			case <-s.Done():
				return
			}
		}
	}()
	return in
}

// Err is why the reader stopped, once Done is closed.
func (in *Inbox) Err() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.err
}

// Gone reports, without waiting, whether the player has gone.
func (in *Inbox) Gone() bool {
	select {
	case <-in.Done:
		return true
	default:
		return false
	}
}
