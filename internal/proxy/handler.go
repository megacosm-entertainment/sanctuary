package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
)

// Messages the gateway itself sends a player.
const (
	msgConnecting   = "Connecting you to a realm...\n"
	msgNoRealm      = "No realm is available right now. Please try again later.\n"
	msgHoldFmt      = "\nThe realm is unavailable for the moment. Hold on: you will be reconnected when it is back (waiting up to %s).\n"
	msgStillWaitFmt = "Still waiting for the realm to come back (up to %s more).\n"
	msgReconnected  = "Reconnected.\n"
	msgGaveUp       = "The realm did not come back in time. Please reconnect later.\n"
	msgShutdown     = "\nThe gateway is shutting down. Goodbye.\n"
)

// Handler routes each player to a realm and relays their session both ways.
// It replaces the stage-01 echo handler.
//
// When the player's realm drains or is lost, the player is held rather than
// disconnected: the gateway owns the socket, so it tells them what is
// happening and re-attaches them when the same realm registers again
// (design §04, "Realm restarts should not disconnect players").
type Handler struct {
	Hub *Hub
	// Realm is the realm to route to; empty means the first registered
	// realm by id. Stage 03's lobby replaces this with the player's choice.
	Realm string
	// Wait is how long a newly connected player waits for a realm to
	// register before being told none is available. Default 10s.
	Wait time.Duration
	// Hold is how long a player whose realm went away is held for it to
	// return. Default 2 minutes (protocol.md §8).
	Hold time.Duration
}

// outcome is how one attachment to a realm ended.
type outcome int

const (
	ended outcome = iota // the session is over
	lost                 // the realm went away; hold the player
)

func (h Handler) ServeSession(ctx context.Context, s *session.Session) {
	wait, hold := h.Wait, h.Hold
	if wait == 0 {
		wait = 10 * time.Second
	}
	if hold == 0 {
		hold = 2 * time.Minute
	}

	// One reader for the whole session: a session is read from one
	// goroutine only, and attachments come and go.
	in := &input{events: make(chan session.Inbound, 64), done: make(chan error, 1)}
	go in.read(s)

	r, ok := h.waitFor(ctx, s, in, h.Realm, wait, false)
	if !ok {
		return
	}
	for {
		if h.relay(ctx, s, in, r) == ended {
			return
		}
		s.Send(session.Text{Text: fmt.Sprintf(msgHoldFmt, spoken(hold))})
		s.Log().Info("holding player for realm", "realm", r.ID, "for", hold)
		if r, ok = h.waitFor(ctx, s, in, r.ID, hold, true); !ok {
			return
		}
		s.Send(session.Text{Text: msgReconnected})
	}
}

type input struct {
	events chan session.Inbound
	done   chan error
}

func (in *input) read(s *session.Session) {
	for {
		ev, err := s.Recv()
		if err != nil {
			in.done <- err
			return
		}
		select {
		case in.events <- ev:
		case <-s.Done():
			return
		}
	}
}

// waitFor waits up to d for realm id (any realm when id is empty) to be
// available, answering the player meanwhile. holding is true when the
// player is already in a game and waiting for their realm to return.
func (h Handler) waitFor(ctx context.Context, s *session.Session, in *input, id string, d time.Duration, holding bool) (*Realm, bool) {
	// Answer at once when the realm is up; otherwise say something, so a
	// screen-reader user is not left with silence.
	quick, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	r, err := h.Hub.pick(quick, id)
	cancel()
	if err == nil {
		return r, true
	}
	if !holding {
		s.Send(session.Text{Text: msgConnecting})
	}

	until := time.Now().Add(d)
	wctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	found := make(chan *Realm, 1)
	go func() {
		if r, err := h.Hub.pick(wctx, id); err == nil {
			found <- r
		}
	}()
	for {
		select {
		case r := <-found:
			return r, true
		case <-wctx.Done():
			switch {
			case ctx.Err() != nil:
				s.Send(session.Text{Text: msgShutdown})
			case holding:
				s.Send(session.Text{Text: msgGaveUp})
			default:
				s.Send(session.Text{Text: msgNoRealm})
			}
			return nil, false
		case ev := <-in.events:
			if _, ok := ev.(session.Line); ok {
				s.Send(session.Text{Text: fmt.Sprintf(msgStillWaitFmt, spoken(time.Until(until)))})
			}
		case <-in.done:
			return nil, false // the player left while waiting
		case <-s.Done():
			return nil, false
		}
	}
}

// relay attaches the player to r and passes events both ways until the
// session ends or the realm goes away.
func (h Handler) relay(ctx context.Context, s *session.Session, in *input, r *Realm) outcome {
	a, err := r.attach(s)
	if err != nil {
		return lost
	}
	log := s.Log().With("realm", r.ID)
	log.Info("routed to realm")
	leave := func(reason, why string) {
		r.detach(s.ID, reason)
		log.Info("left realm", "reason", reason, "why", why)
	}

	for {
		select {
		case <-ctx.Done():
			s.Send(session.Text{Text: msgShutdown})
			leave(realmproto.ClosedShutdown, "gateway shutdown")
			return ended
		case <-a.realmClosed:
			if a.closeReason == realmproto.ClosedDrain {
				leave("", "realm draining")
				return lost
			}
			leave("", "realm ended the session")
			return ended
		case <-r.Gone():
			leave("", "realm link lost")
			return lost
		case <-in.done:
			leave(realmproto.ClosedDisconnected, "player disconnected")
			return ended
		case <-s.Done():
			reason := realmproto.ClosedDisconnected
			if errors.Is(s.Err(), session.ErrOverflow) {
				reason = realmproto.ClosedOverflow
			}
			leave(reason, "session ended")
			return ended
		case ev := <-in.events:
			m := toRealm(s.ID, ev)
			if m == nil {
				continue
			}
			// Writer.Send never blocks, so a slow realm cannot stall this
			// player's reads, and one player's input cannot hold up anyone
			// else's.
			switch err := r.w.Send(m); {
			case err == nil:
			case errors.Is(err, realmproto.ErrInvalidField):
				// Not silently (RT-3-2): say which kind and why (validation
				// errors name the field, never its content: player text or GMCP).
				log.Warn("input not forwarded to the realm: over the protocol's limits", "type", m.Type(), "err", err)
			case errors.Is(err, realmproto.ErrSessionBacklog):
				leave(realmproto.ClosedOverflow, "input backlog")
				return ended
			default:
				// The realm's link is failing; this player noticed first.
				leave("", "realm link failing")
				return lost
			}
		}
	}
}

func toRealm(id uint64, ev session.Inbound) realmproto.Message {
	switch v := ev.(type) {
	case session.Line:
		return &realmproto.Input{Session: id, Text: v.Text}
	case session.GMCP:
		return &realmproto.GMCP{Session: id, Package: v.Package, Data: v.Data}
	case session.ClientUpdate:
		return &realmproto.Client{Session: id, Client: realmproto.ClientFrom(v.Info)}
	}
	return nil
}

// spoken renders a wait the way a person would say it ("2 minutes",
// "45 seconds"): players read these, often through a screen reader, so
// "2m0s" will not do.
func spoken(d time.Duration) string {
	unit := func(n int64, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	if d >= time.Minute {
		return unit(int64((d+30*time.Second)/time.Minute), "minute")
	}
	s := int64((d + time.Second/2) / time.Second)
	if s < 1 {
		s = 1
	}
	return unit(s, "second")
}
