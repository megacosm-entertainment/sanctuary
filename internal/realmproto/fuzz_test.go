package realmproto

import (
	"bytes"
	"testing"
)

// FuzzDecode checks Decode on arbitrary payloads from either side: it never
// panics, anything it accepts re-encodes within the frame limit, and the
// re-encoded form decodes to the same message type. That last property is
// what lets a peer forward or replay a message it accepted.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		`{"type":"hello","versions":[1],"realm":"live","name":"Sanctuary","build":"dev"}`,
		`{"type":"session.open","session":1,"transport":"telnet","secure":false,"client":{"name":"mushclient","mtts":13,"width":80,"height":26}}`,
		`{"type":"input","session":1,"text":"look"}`,
		`{"type":"text","session":1,"text":"Mara bows.","meta":{"kind":"pose","voice":"ic","scene":"s1"}}`,
		`{"type":"gmcp","session":1,"package":"Char.Vitals","data":{"hp":1}}`,
		`{"type":"gmcp","session":1,"package":"Core.Ping","data":null}`,
		`{"type":"drain","deadline_ms":5000}`,
		`{"type":"scene.start"}`,
		`{"type":"text","session":9007199254740993}`,
		`[]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), true)
		f.Add([]byte(s), false)
	}
	f.Fuzz(func(t *testing.T, payload []byte, fromRealm bool) {
		from := FromGateway
		if fromRealm {
			from = FromRealm
		}
		m, err := Decode(payload, from)
		if err != nil {
			return
		}
		if u, ok := m.(*Unknown); ok {
			// Unknown types carry only a capped name.
			if len(u.Name) > maxLabel {
				t.Fatalf("Unknown name not capped: %d bytes", len(u.Name))
			}
			return
		}
		out, err := Encode(m)
		if err != nil {
			t.Fatalf("Encode of accepted %s failed: %v", payload, err)
		}
		if !bytes.HasPrefix(out, []byte(`{"type":`)) {
			t.Fatalf("Encode(%T) = %s, want type first", m, out)
		}
		m2, err := Decode(out, from)
		if err != nil {
			t.Fatalf("re-decode of %s failed: %v", out, err)
		}
		if m2.Type() != m.Type() || SessionOf(m2) != SessionOf(m) {
			t.Fatalf("round trip changed %s/%d to %s/%d", m.Type(), SessionOf(m), m2.Type(), SessionOf(m2))
		}
	})
}
