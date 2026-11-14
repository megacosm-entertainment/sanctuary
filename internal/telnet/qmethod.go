package telnet

// RFC 1143 "Q method" option negotiation.
//
// Each option has two independent sides: "us" (we perform the option; WILL
// and WONT from us, DO and DONT from the peer) and "him" (the peer performs
// it). Each side is in one of four states, plus a one-bit queue that records
// a change of mind while a request is outstanding. The machine never answers
// an acknowledgement with another request, so a misbehaving client cannot
// drive a negotiation loop.

type qstate uint8

const (
	qNo qstate = iota
	qYes
	qWantNo
	qWantYes
)

type qside struct {
	state    qstate
	opposite bool // queue bit: EMPTY when false, OPPOSITE when true
	// lateAcks counts our disables not yet acknowledged. A disable cannot
	// be refused (RFC 854), so we treat it as done when we send it rather
	// than waiting in WANTNO: some clients (TinTin++ 2.02) never answer
	// WONT ECHO, and waiting would hold back every later WILL ECHO, so
	// passwords would be shown. A late acknowledgement is swallowed.
	lateAcks int
}

type qoption struct {
	us, him qside
}

// qmachine holds negotiation state for every option. It calls send to emit
// commands and changed when a side enters or leaves qYes.
type qmachine struct {
	opts      [256]qoption
	allowUs   func(opt byte) bool
	allowHim  func(opt byte) bool
	send      func(cmd, opt byte)
	changed   func(opt byte, us, enabled bool)
	violation func(opt byte, what string) // protocol errors, for logging
}

func (m *qmachine) usEnabled(opt byte) bool  { return m.opts[opt].us.state == qYes }
func (m *qmachine) himEnabled(opt byte) bool { return m.opts[opt].him.state == qYes }

// recv handles WILL/WONT/DO/DONT from the peer.
func (m *qmachine) recv(cmd, opt byte) {
	switch cmd {
	case WILL:
		m.recvEnable(&m.opts[opt].him, opt, false, DO, DONT)
	case WONT:
		m.recvDisable(&m.opts[opt].him, opt, false, DO, DONT)
	case DO:
		m.recvEnable(&m.opts[opt].us, opt, true, WILL, WONT)
	case DONT:
		m.recvDisable(&m.opts[opt].us, opt, true, WILL, WONT)
	}
}

// recvEnable handles WILL (for him) or DO (for us). yes/no are the commands
// we send for that side: DO/DONT for him, WILL/WONT for us.
func (m *qmachine) recvEnable(s *qside, opt byte, us bool, yes, no byte) {
	switch s.state {
	case qNo:
		allow := m.allowHim
		if us {
			allow = m.allowUs
		}
		if allow(opt) {
			s.state = qYes
			m.send(yes, opt)
			m.changed(opt, us, true)
		} else {
			m.send(no, opt)
		}
	case qYes:
		// Already enabled; ignore. Answering would risk a loop.
	case qWantNo:
		if !s.opposite {
			// Our disable was answered with an enable: peer error.
			s.state = qNo
			m.violation(opt, "enable in answer to disable")
		} else {
			s.state = qYes
			s.opposite = false
			m.changed(opt, us, true)
		}
	case qWantYes:
		// Replies come in order: an answer to our enable means no
		// acknowledgement of an earlier disable is still on its way.
		s.lateAcks = 0
		if !s.opposite {
			s.state = qYes
			m.changed(opt, us, true)
		} else {
			// We changed our mind while asking: disable at once, as in ask.
			s.state = qNo
			s.opposite = false
			s.lateAcks++
			m.send(no, opt)
		}
	}
}

// recvDisable handles WONT (for him) or DONT (for us).
func (m *qmachine) recvDisable(s *qside, opt byte, us bool, yes, no byte) {
	if s.lateAcks > 0 && (s.state == qNo || s.state == qWantYes) {
		// The acknowledgement of a disable we already treated as done
		// (replies come in order, so it precedes any answer to a later
		// enable). Not a refusal.
		s.lateAcks--
		return
	}
	switch s.state {
	case qNo:
		// Already disabled; ignore.
	case qYes:
		s.state = qNo
		// Stop using the option before acknowledging: for MCCP2 the
		// compressed stream must end before the WONT goes out.
		m.changed(opt, us, false)
		m.send(no, opt)
	case qWantNo:
		if !s.opposite {
			// Ack of our disable; changed(false) already fired in ask.
			s.state = qNo
		} else {
			s.state = qWantYes
			s.opposite = false
			m.send(yes, opt)
		}
	case qWantYes:
		// Refused (or answered our disable-queued request); either way, off.
		s.state = qNo
		s.opposite = false
	}
}

// askUs requests that we enable (WILL) or disable (WONT) opt.
func (m *qmachine) askUs(opt byte, enable bool) {
	m.ask(&m.opts[opt].us, opt, true, enable, WILL, WONT)
}

// askHim requests that the peer enable (DO) or disable (DONT) opt.
func (m *qmachine) askHim(opt byte, enable bool) {
	m.ask(&m.opts[opt].him, opt, false, enable, DO, DONT)
}

func (m *qmachine) ask(s *qside, opt byte, us, enable bool, yes, no byte) {
	if enable {
		switch s.state {
		case qNo:
			s.state = qWantYes
			m.send(yes, opt)
		case qWantNo:
			s.opposite = true
		case qWantYes:
			s.opposite = false
		}
		return
	}
	switch s.state {
	case qYes:
		// Off from now (a disable cannot be refused): stop using it before
		// saying so, which MCCP2 needs, and expect an acknowledgement that
		// may never come (see lateAcks).
		s.state = qNo
		s.lateAcks++
		m.changed(opt, us, false)
		m.send(no, opt)
	case qWantNo:
		s.opposite = false
	case qWantYes:
		s.opposite = true
	}
}
