package telnet

import (
	"strconv"
	"strings"
)

// Describe renders a telnet byte stream symbolically, e.g.
// `IAC DO TTYPE, "hello\r\n", IAC SB TTYPE "\x01" IAC SE`. It is for
// test failure messages and debugging; it does not validate.
func Describe(b []byte) string {
	var parts []string
	var text []byte
	flushText := func() {
		if len(text) > 0 {
			parts = append(parts, strconv.Quote(string(text)))
			text = text[:0]
		}
	}
	for i := 0; i < len(b); i++ {
		if b[i] != IAC || i+1 >= len(b) {
			text = append(text, b[i])
			continue
		}
		flushText()
		cmd := b[i+1]
		i++
		switch cmd {
		case IAC:
			parts = append(parts, "IAC IAC")
		case WILL, WONT, DO, DONT:
			if i+1 < len(b) {
				i++
				parts = append(parts, "IAC "+commandName(cmd)+" "+OptionName(b[i]))
			} else {
				parts = append(parts, "IAC "+commandName(cmd))
			}
		case SB:
			s := "IAC SB"
			if i+1 < len(b) {
				i++
				s += " " + OptionName(b[i])
			}
			var payload []byte
			for i+1 < len(b) && !(b[i+1] == IAC && i+2 < len(b) && b[i+2] == SE) {
				i++
				if b[i] == IAC && i+1 < len(b) && b[i+1] == IAC {
					i++
				}
				payload = append(payload, b[i])
			}
			if len(payload) > 0 {
				s += " " + strconv.Quote(string(payload))
			}
			if i+2 < len(b) {
				i += 2
				s += " IAC SE"
			}
			parts = append(parts, s)
		default:
			parts = append(parts, "IAC "+commandName(cmd))
		}
	}
	flushText()
	if len(parts) == 0 {
		return "(nothing)"
	}
	return strings.Join(parts, ", ")
}

func commandName(c byte) string {
	switch c {
	case SE:
		return "SE"
	case NOP:
		return "NOP"
	case GA:
		return "GA"
	case SB:
		return "SB"
	case WILL:
		return "WILL"
	case WONT:
		return "WONT"
	case DO:
		return "DO"
	case DONT:
		return "DONT"
	case EOR:
		return "EOR"
	case EC:
		return "EC"
	case EL:
		return "EL"
	case AYT:
		return "AYT"
	}
	return "cmd" + strconv.Itoa(int(c))
}
