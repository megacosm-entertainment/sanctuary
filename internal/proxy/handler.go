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
	msgEnteringFmt  = "Entering %[1]s. '%[2]slobby' comes back out; '%[2]shelp' lists the gateway's commands.\n"
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
	// Prefix marks gateway commands (see DefaultPrefix); DefaultPrefix if empty.
	Prefix string
}

// outcome is how one attachment to a realm ended.
type outcome int

const (
	ended    outcome = iota // the player is gone, or the gateway is stopping
	lost                    // the realm went away; hold the player
	returned                // the realm ended the session; the player is still here
)

// Outcome is how a player's time in a realm ended, for a caller that has
// somewhere to send them next (the lobby).
type Outcome int

const (
	// Gone: the player disconnected, the gateway is shutting down, or the
	// session ended otherwise. Nothing more can be sent.
	Gone Outcome = iota
	// Back: the realm ended the session (the player quit in the realm, or
	// no realm was available), and the player is still connected.
	Back
)

// ServeSession routes a player straight to a realm, for a gateway without
// a lobby: the session ends when the player leaves the realm.
func (h Handler) ServeSession(ctx context.Context, s *session.Session) {
	h.Play(ctx, s, session.NewInbox(s))
}

// Play routes a player to Realm (the first realm when empty) and relays
// until they leave it, holding them through drains and realm restarts.
// in is the session's one reader, shared with whatever runs before and
// after (the lobby).
func (h Handler) Play(ctx context.Context, s *session.Session, in *session.Inbox) Outcome {
	wait, hold := h.Wait, h.Hold
	if wait == 0 {
		wait = 10 * time.Second
	}
	if hold == 0 {
		hold = 2 * time.Minute
	}
	r, ok, quit := h.waitFor(ctx, s, in, h.Realm, wait, false)
	if quit {
		return Gone
	}
	if !ok {
		return backIfConnected(ctx, s, in)
	}
	p := h.CommandPrefix()
	s.Send(session.Text{Text: fmt.Sprintf(msgEnteringFmt, RealmLabel(RealmInfo{r.ID, r.Name, r.Build}), p)})
	for {
		switch h.relay(ctx, s, in, r) {
		case ended:
			return Gone
		case returned:
			return Back
		}
		s.Send(session.Text{Text: fmt.Sprintf(msgHoldFmt, spoken(hold))})
		s.Log().Info("holding player for realm", "realm", r.ID, "for", hold)
		if r, ok, quit = h.waitFor(ctx, s, in, r.ID, hold, true); quit {
			return Gone
		} else if !ok {
			return backIfConnected(ctx, s, in)
		}
		s.Send(session.Text{Text: msgReconnected})
	}
}

// backIfConnected is the outcome when no realm could be reached: back to
// the lobby, unless the player or the gateway is gone.
func backIfConnected(ctx context.Context, s *session.Session, in *session.Inbox) Outcome {
	select {
	case <-ctx.Done():
		return Gone
	case <-s.Done():
		return Gone
	default:
	}
	if in.Gone() {
		return Gone
	}
	return Back
}

// waitFor waits up to d for realm id (any realm when id is empty) to be
// available, answering the player meanwhile. holding is true when the
// player is already in a game and waiting for their realm to return.
//
// The player may leave with a gateway command: >lobby gives ok false,
// >quit gives quit true.
func (h Handler) waitFor(ctx context.Context, s *session.Session, in *session.Inbox, id string, d time.Duration, holding bool) (r *Realm, ok, quit bool) {
	// Answer at once when the realm is up; otherwise say something, so a
	// screen-reader user is not left with silence.
	quick, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	r, err := h.Hub.pick(quick, id)
	cancel()
	if err == nil {
		return r, true, false
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
			return r, true, false
		case <-wctx.Done():
			switch {
			case ctx.Err() != nil:
				s.Send(session.Text{Text: msgShutdown})
			case holding:
				s.Send(session.Text{Text: msgGaveUp})
			default:
				s.Send(session.Text{Text: msgNoRealm})
			}
			return nil, false, false
		case ev := <-in.Events:
			l, isLine := ev.(session.Line)
			if !isLine {
				continue
			}
			switch h.command(s, l.Text, id) {
			case toLobby:
				return nil, false, false
			case quitAll:
				return nil, false, true
			case notCommand:
				s.Send(session.Text{Text: fmt.Sprintf(msgStillWaitFmt, spoken(time.Until(until)))})
			}
		case <-in.Done:
			return nil, false, false // the player left while waiting
		case <-s.Done():
			return nil, false, false
		}
	}
}

// relay attaches the player to r and passes events both ways until the
// session ends or the realm goes away.
func (h Handler) relay(ctx context.Context, s *session.Session, in *session.Inbox, r *Realm) outcome {
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
				restoreEcho(s, a)
				leave("", "realm draining")
				return lost
			}
			leave("", "realm ended the session")
			return returned
		case <-r.Gone():
			restoreEcho(s, a)
			leave("", "realm link lost")
			return lost
		case <-in.Done:
			leave(realmproto.ClosedDisconnected, "player disconnected")
			return ended
		case <-s.Done():
			reason := realmproto.ClosedDisconnected
			if errors.Is(s.Err(), session.ErrOverflow) {
				reason = realmproto.ClosedOverflow
			}
			leave(reason, "session ended")
			return ended
		case ev := <-in.Events:
			// Gateway commands never reach the realm, except while the
			// realm has asked for hidden input: that line may be a password
			// that happens to start with the prefix.
			if l, ok := ev.(session.Line); ok && !a.hidden.Load() {
				switch h.command(s, l.Text, r.ID) {
				case toLobby:
					leave(realmproto.ClosedQuit, "player went to the lobby")
					return returned
				case quitAll:
					leave(realmproto.ClosedQuit, "player quit")
					return ended
				case stay:
					continue
				}
			}
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
				restoreEcho(s, a)
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

// restoreEcho turns local echo back on if the realm that is going away had
// turned it off (a password prompt) and never turned it back on. A held
// player would otherwise type blind, and the next realm would inherit it.
func restoreEcho(s *session.Session, a *attached) {
	if a.hidden.Load() {
		s.Send(session.InputMode{Hidden: false})
	}
}
