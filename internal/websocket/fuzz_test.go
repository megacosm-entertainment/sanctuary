package websocket

import (
	"io"
	"net"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzReadMessage feeds arbitrary client bytes to the frame reader. It must
// never panic or hang, never return a message over MaxMessage, and never
// return a text message that is not UTF-8.
func FuzzReadMessage(f *testing.F) {
	mask := []byte{1, 2, 3, 4}
	f.Add(append([]byte{0x81, 0x85}, append(mask, 'h'^1, 'e'^2, 'l'^3, 'l'^4, 'o'^1)...))
	f.Add(append([]byte{0x01, 0x81}, append(mask, 'a'^1)...)) // unfinished fragment
	f.Add([]byte{0x88, 0x81, 1, 2, 3, 4, 0x03})               // one-byte close payload
	f.Add([]byte{0x82, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		go func() {
			client.Write(in)
			client.Close()
		}()
		go io.Copy(io.Discard, client) // absorb pongs and close frames
		c := NewServerConn(server)
		c.WriteTimeout = time.Second
		for i := 0; i < 64; i++ {
			op, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if len(msg) > MaxMessage {
				t.Fatalf("message of %d bytes exceeds MaxMessage", len(msg))
			}
			if op == OpText && !utf8.Valid(msg) {
				t.Fatalf("text message is not UTF-8: %q", msg)
			}
		}
	})
}
