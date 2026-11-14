package proxy

import (
	"context"
	"errors"
	"time"

	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
)

// Messages the gateway itself sends a player.
const (
	msgConnecting = "Connecting you to a realm...\n"
	msgNoRealm    = "No realm is available right now. Please try again later.\n"
	msgRealmLost  = "\nThe realm has gone away. Please reconnect in a moment.\n"
	msgShutdown   = "\nThe gateway is shutting down. Goodbye.\n"
)

// Handler routes each player to a realm and relays their session both ways.
// It replaces the stage-01 echo handler.
type Handler struct {
	Hub *Hub
	// Realm is the realm to route to; empty means the first registered
	// realm by id. Stage 03's lobby replaces this with the player's choice.
	Realm string
	// Wait is how long a player is held for a realm to register before
	// being told none is available. Default 10s.
	Wait time.Duration
}

func (h Handler) ServeSession(ctx context.Context, s *session.Session) {
	wait := h.Wait
	if wait == 0 {
		wait = 10 * time.Second
	}
	r, err := h.pick(ctx, s, wait)
	if err != nil {
		return
	}
	a, err := r.attach(s)
	if err != nil {
		s.Send(session.Text{Text: msgRealmLost})
		return
	}
	log := s.Log().With("realm", r.ID)
	log.Info("routed to realm")

	// Player events go to the realm from their own goroutine. Writer.Send
	// never blocks, so a slow realm cannot stall this player's reads, and
	// one player's input cannot hold up anyone else's.
	inputDone := make(chan error, 1)
	go func() { inputDone <- relayInput(s, r) }()

	reason := realmproto.ClosedDisconnected
	select {
	case <-ctx.Done():
		s.Send(session.Text{Text: msgShutdown})
		reason = realmproto.ClosedShutdown
	case <-a.realmClosed:
		reason = "" // the realm ended it; nothing to tell the realm
	case <-r.Gone():
		s.Send(session.Text{Text: msgRealmLost})
		reason = ""
	case err := <-inputDone:
		switch {
		case errors.Is(err, realmproto.ErrSessionBacklog):
			reason = realmproto.ClosedOverflow
		case errors.Is(err, realmproto.ErrStalled) || errors.Is(err, realmproto.ErrWriterClosed):
			// The realm's link is failing; this player noticed first.
			s.Send(session.Text{Text: msgRealmLost})
			reason = ""
		}
	case <-s.Done():
		if errors.Is(s.Err(), session.ErrOverflow) {
			reason = realmproto.ClosedOverflow
		}
	}
	r.detach(s.ID, reason)
	log.Info("left realm", "reason", reason)
}

func (h Handler) pick(ctx context.Context, s *session.Session, wait time.Duration) (*Realm, error) {
	// Answer at once when a realm is up; say something if the player has
	// to wait, so a screen-reader user is not left with silence.
	fast, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	r, err := h.Hub.pick(fast, h.Realm)
	cancel()
	if err == nil {
		return r, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.Send(session.Text{Text: msgConnecting})
	slow, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	r, err = h.Hub.pick(slow, h.Realm)
	if err != nil {
		if ctx.Err() != nil {
			s.Send(session.Text{Text: msgShutdown})
		} else {
			s.Send(session.Text{Text: msgNoRealm})
		}
		return nil, err
	}
	return r, nil
}

// relayInput forwards a player's events until their session ends or the
// realm cannot take more of this player's input.
func relayInput(s *session.Session, r *Realm) error {
	for {
		ev, err := s.Recv()
		if err != nil {
			return err
		}
		var m realmproto.Message
		switch v := ev.(type) {
		case session.Line:
			m = &realmproto.Input{Session: s.ID, Text: v.Text}
		case session.GMCP:
			m = &realmproto.GMCP{Session: s.ID, Package: v.Package, Data: v.Data}
		case session.ClientUpdate:
			m = &realmproto.Client{Session: s.ID, Client: realmproto.ClientFrom(v.Info)}
		default:
			continue
		}
		if err := r.w.Send(m); err != nil {
			if errors.Is(err, realmproto.ErrInvalidField) {
				continue // e.g. a GMCP payload over the protocol's cap: drop it
			}
			return err
		}
	}
}
