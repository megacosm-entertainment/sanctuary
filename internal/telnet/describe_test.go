package telnet

import "testing"

func TestDescribe(t *testing.T) {
	tests := []struct {
		in   []byte
		want string
	}{
		{nil, "(nothing)"},
		{[]byte("hi"), `"hi"`},
		{[]byte{IAC, DO, OptTTYPE, 'x', IAC, EOR}, `IAC DO TTYPE, "x", IAC EOR`},
		{[]byte{IAC, SB, OptTTYPE, TTypeSend, IAC, SE}, `IAC SB TTYPE "\x01" IAC SE`},
		{[]byte{IAC, SB, OptNAWS, 0, IAC, IAC, 0, 24, IAC, SE}, `IAC SB NAWS "\x00\xff\x00\x18" IAC SE`},
	}
	for _, tt := range tests {
		if got := Describe(tt.in); got != tt.want {
			t.Errorf("Describe(%v) = %s, want %s", tt.in, got, tt.want)
		}
	}
}
