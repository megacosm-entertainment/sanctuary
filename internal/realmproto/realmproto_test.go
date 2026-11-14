package realmproto_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"sanctuary/internal/realmproto"
	"sanctuary/internal/session"
)

const timeout = 2 * time.Second

func frame(payload string) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(payload))); err != nil {
		panic(err)
	}
	buf.WriteString(payload)
	return buf.Bytes()
}

func intp(n int) *int { return &n }

// ── Framing (protocol.md §2) ─────────────────────────────────

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := []byte(`{"type":"ping","n":1}`)
	if err := realmproto.WriteFrame(&buf, want); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := realmproto.ReadFrame(&buf, realmproto.MaxFrame)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadFrame = %q, want %q", got, want)
	}
}

// failAfter returns its prefix and then fails, so a test can prove the
// reader never asked for more than the header.
type failAfter struct {
	prefix []byte
	read   bool
}

func (f *failAfter) Read(p []byte) (int, error) {
	if len(f.prefix) == 0 {
		f.read = true
		return 0, errors.New("payload was read")
	}
	n := copy(p, f.prefix)
	f.prefix = f.prefix[n:]
	return n, nil
}

func TestOversizeFrameRejectedBeforePayload(t *testing.T) {
	// Header announcing one byte over the limit, and no payload: a reader
	// that tried to read the payload would hit failAfter's error instead.
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, realmproto.MaxHello+1)
	r := &failAfter{prefix: hdr}
	_, err := realmproto.ReadFrame(r, realmproto.MaxHello)
	if !errors.Is(err, realmproto.ErrFrameTooLarge) {
		t.Fatalf("ReadFrame(len %d, limit %d) err = %v, want ErrFrameTooLarge",
			realmproto.MaxHello+1, realmproto.MaxHello, err)
	}
	if r.read {
		t.Fatal("ReadFrame read past the header of an oversize frame")
	}
}

func TestFrameAtLimitAccepted(t *testing.T) {
	payload := strings.Repeat("x", realmproto.MaxHello)
	got, err := realmproto.ReadFrame(bytes.NewReader(frame(payload)), realmproto.MaxHello)
	if err != nil || len(got) != realmproto.MaxHello {
		t.Fatalf("ReadFrame(exactly the limit) = %d bytes, %v; want %d bytes", len(got), err, realmproto.MaxHello)
	}
}

func TestBadFrames(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		// Every frame carries a JSON object, so length 0 is never valid.
		{"empty frame", frame("")},
		{"truncated header", []byte{0, 0}},
		{"truncated payload", frame(`{"type":"ping"}`)[:8]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := realmproto.ReadFrame(bytes.NewReader(c.in), realmproto.MaxFrame); err == nil {
				t.Fatalf("ReadFrame(% x) succeeded, want an error", c.in)
			}
		})
	}
}

func TestWriteFrameRefusesOversize(t *testing.T) {
	var buf bytes.Buffer
	err := realmproto.WriteFrame(&buf, make([]byte, realmproto.MaxFrame+1))
	if !errors.Is(err, realmproto.ErrFrameTooLarge) {
		t.Fatalf("WriteFrame(MaxFrame+1) err = %v, want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("WriteFrame wrote %d bytes of a refused frame", buf.Len())
	}
}

// ── Messages (protocol.md §4–§8) ─────────────────────────────

// Every message type, as its sender would send it, survives encode and
// decode unchanged.
func TestRoundTrip(t *testing.T) {
	cases := []struct {
		from realmproto.Sender
		msg  realmproto.Message
	}{
		{realmproto.FromRealm, &realmproto.Hello{Versions: []int{1}, Realm: "live", Name: "Sanctuary", Build: "1c3784d", Fingerprint: "sha256:abc"}},
		{realmproto.FromGateway, &realmproto.Welcome{Version: 1, Gateway: "dev"}},
		{realmproto.FromGateway, &realmproto.Welcome{Version: 1, Gateway: "dev", CommandPrefix: "/"}},
		{realmproto.FromGateway, &realmproto.Reject{Reason: realmproto.RejectUnsupportedVersion, Versions: []int{1}}},
		{realmproto.FromGateway, &realmproto.SessionOpen{Session: 7, Transport: "ws/gmcp", Secure: true,
			Client: realmproto.ClientInfo{Name: "mushclient", Terminal: "ANSI", MTTS: intp(13), Charset: "UTF-8", Width: 80, Height: 26}}},
		{realmproto.FromGateway, &realmproto.SessionOpen{Session: 8, Transport: "telnet+tls", Secure: true,
			Account: &realmproto.AccountInfo{ID: "0123456789abcdef0123456789abcdef", Name: "Mara"}}},
		{realmproto.FromGateway, &realmproto.Input{Session: 7, Text: "look"}},
		{realmproto.FromGateway, &realmproto.Client{Session: 7, Client: realmproto.ClientInfo{Width: 120, Height: 40}}},
		{realmproto.FromGateway, &realmproto.SessionClosed{Session: 7, Reason: realmproto.ClosedQuit}},
		{realmproto.FromRealm, &realmproto.Text{Session: 7, Text: "Mara draws her sword.",
			Meta: &realmproto.Meta{Kind: realmproto.KindPose, Voice: realmproto.VoiceIC, Scene: "scene-42", Actor: "char:mara"}}},
		// Hack-and-slash output with no scene at all is a normal message.
		{realmproto.FromRealm, &realmproto.Text{Session: 7, Text: "You hit the orc."}},
		{realmproto.FromRealm, &realmproto.Prompt{Session: 7, Text: "> "}},
		{realmproto.FromRealm, &realmproto.InputMode{Session: 7, Hidden: true}},
		{realmproto.FromRealm, &realmproto.SessionClose{Session: 7, Reason: "quit"}},
		{realmproto.FromRealm, &realmproto.GMCP{Session: 7, Package: "Char.Vitals", Data: json.RawMessage(`{"hp":10}`)}},
		{realmproto.FromGateway, &realmproto.GMCP{Session: 7, Package: "Core.Ping"}},
		{realmproto.FromGateway, &realmproto.Ping{N: 3}},
		{realmproto.FromRealm, &realmproto.Pong{N: 3}},
		{realmproto.FromGateway, &realmproto.Shutdown{}},
		{realmproto.FromRealm, &realmproto.Drain{DeadlineMS: 30000}},
		{realmproto.FromRealm, &realmproto.Drained{}},
	}
	for _, c := range cases {
		t.Run(c.msg.Type(), func(t *testing.T) {
			payload, err := realmproto.Encode(c.msg)
			if err != nil {
				t.Fatalf("Encode(%+v): %v", c.msg, err)
			}
			if !bytes.HasPrefix(payload, []byte(`{"type":"`+c.msg.Type()+`"`)) {
				t.Errorf("Encode = %s, want it to start with the type", payload)
			}
			got, err := realmproto.Decode(payload, c.from)
			if err != nil {
				t.Fatalf("Decode(%s): %v", payload, err)
			}
			if !reflect.DeepEqual(got, c.msg) {
				t.Fatalf("Decode(Encode(m)) = %+v, want %+v", got, c.msg)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	long := strings.Repeat("a", 65)
	cases := []struct {
		name    string
		from    realmproto.Sender
		payload string
		want    error
	}{
		// encoding/json would quietly turn this into U+FFFD.
		{"invalid UTF-8", realmproto.FromRealm, "{\"type\":\"text\",\"session\":1,\"text\":\"\xff\"}", realmproto.ErrInvalidUTF8},
		{"array", realmproto.FromRealm, `[1]`, realmproto.ErrNotObject},
		{"null", realmproto.FromRealm, `null`, realmproto.ErrNotObject},
		{"trailing data", realmproto.FromRealm, `{"type":"drained"} {}`, realmproto.ErrNotObject},
		{"no type", realmproto.FromRealm, `{"session":1}`, realmproto.ErrMissingType},
		{"empty type", realmproto.FromRealm, `{"type":""}`, realmproto.ErrMissingType},
		// A realm must not be able to pretend to be the gateway, or forge input.
		{"realm sends welcome", realmproto.FromRealm, `{"type":"welcome","version":1}`, realmproto.ErrWrongSender},
		{"realm sends input", realmproto.FromRealm, `{"type":"input","session":1,"text":"x"}`, realmproto.ErrWrongSender},
		{"gateway sends text", realmproto.FromGateway, `{"type":"text","session":1,"text":"x"}`, realmproto.ErrWrongSender},
		{"session zero", realmproto.FromRealm, `{"type":"text","session":0,"text":"x"}`, realmproto.ErrInvalidField},
		{"session missing", realmproto.FromRealm, `{"type":"prompt","text":"x"}`, realmproto.ErrInvalidField},
		{"session negative", realmproto.FromRealm, `{"type":"prompt","session":-1}`, realmproto.ErrInvalidField},
		{"session above 2^53", realmproto.FromRealm, `{"type":"prompt","session":9007199254740993}`, realmproto.ErrInvalidField},
		{"session as string", realmproto.FromRealm, `{"type":"prompt","session":"1"}`, realmproto.ErrInvalidField},
		{"hello without versions", realmproto.FromRealm, `{"type":"hello","realm":"live"}`, realmproto.ErrInvalidField},
		{"hello version zero", realmproto.FromRealm, `{"type":"hello","versions":[0],"realm":"live"}`, realmproto.ErrInvalidField},
		{"hello realm with spaces", realmproto.FromRealm, `{"type":"hello","versions":[1],"realm":"my realm"}`, realmproto.ErrInvalidField},
		// protocol.md §4: a realm id is 1-32 characters.
		{"hello realm id of 33", realmproto.FromRealm, `{"type":"hello","versions":[1],"realm":"` + strings.Repeat("a", 33) + `"}`, realmproto.ErrInvalidField},
		{"hello name too long", realmproto.FromRealm, `{"type":"hello","versions":[1],"realm":"live","name":"` + long + `"}`, realmproto.ErrInvalidField},
		{"input too long", realmproto.FromGateway, `{"type":"input","session":1,"text":"` + strings.Repeat("a", realmproto.MaxInput+1) + `"}`, realmproto.ErrInvalidField},
		{"gmcp bad package", realmproto.FromRealm, `{"type":"gmcp","session":1,"package":"Bad Name"}`, realmproto.ErrInvalidField},
		{"meta bad voice", realmproto.FromRealm, `{"type":"text","session":1,"text":"x","meta":{"voice":"loud"}}`, realmproto.ErrInvalidField},
		// Scene ids may reach GMCP and logs, so no quotes or spaces.
		{"meta scene with quote", realmproto.FromRealm, `{"type":"text","session":1,"text":"x","meta":{"scene":"a\"b"}}`, realmproto.ErrInvalidField},
		// protocol.md §2: names are lowercase and appear once. encoding/json
		// alone would read the first as hello and the second as the last type.
		{"type in capitals", realmproto.FromRealm, `{"type":"text","TYPE":"hello","session":1,"text":"x"}`, realmproto.ErrKeySpelling},
		{"type twice", realmproto.FromRealm, `{"type":"text","type":"drained","session":1,"text":"x"}`, realmproto.ErrKeySpelling},
		{"session in mixed case", realmproto.FromRealm, `{"type":"prompt","Session":1}`, realmproto.ErrKeySpelling},
		{"meta key repeated", realmproto.FromRealm, `{"type":"text","session":1,"text":"x","meta":{"kind":"pose","kind":"system"}}`, realmproto.ErrKeySpelling},
		{"client key in capitals", realmproto.FromGateway, `{"type":"client","session":1,"client":{"Width":80}}`, realmproto.ErrKeySpelling},
		{"meta kind uppercase", realmproto.FromRealm, `{"type":"text","session":1,"text":"x","meta":{"kind":"POSE"}}`, realmproto.ErrInvalidField},
		{"drain without deadline", realmproto.FromRealm, `{"type":"drain"}`, realmproto.ErrInvalidField},
		{"window wider than NAWS allows", realmproto.FromGateway, `{"type":"client","session":1,"client":{"width":70000}}`, realmproto.ErrInvalidField},
		{"command prefix a letter", realmproto.FromGateway, `{"type":"welcome","version":1,"command_prefix":"a"}`, realmproto.ErrInvalidField},
		{"command prefix two characters", realmproto.FromGateway, `{"type":"welcome","version":1,"command_prefix":">>"}`, realmproto.ErrInvalidField},
		{"command prefix a space", realmproto.FromGateway, `{"type":"welcome","version":1,"command_prefix":" "}`, realmproto.ErrInvalidField},
		{"account without id", realmproto.FromGateway, `{"type":"session.open","session":1,"transport":"telnet","account":{"name":"Mara"}}`, realmproto.ErrInvalidField},
		{"account name with a space", realmproto.FromGateway, `{"type":"session.open","session":1,"transport":"telnet","account":{"id":"a1","name":"Ma ra"}}`, realmproto.ErrInvalidField},
		{"account name too long", realmproto.FromGateway, `{"type":"session.open","session":1,"transport":"telnet","account":{"id":"a1","name":"` + strings.Repeat("a", 33) + `"}}`, realmproto.ErrInvalidField},
		{"account key in capitals", realmproto.FromGateway, `{"type":"session.open","session":1,"transport":"telnet","account":{"id":"a1","Name":"Mara"}}`, realmproto.ErrKeySpelling},
		{"account key in capitals outside", realmproto.FromGateway, `{"type":"session.open","session":1,"transport":"telnet","Account":{"id":"a1","name":"Mara"}}`, realmproto.ErrKeySpelling},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := realmproto.Decode([]byte(c.payload), c.from)
			if !errors.Is(err, c.want) {
				t.Fatalf("Decode(%s) = %+v, %v; want error %v", c.payload, m, err, c.want)
			}
		})
	}
}

// protocol.md §2: unknown types are ignored, so a newer peer can add
// optional messages without a version bump.
func TestUnknownTypeIsNotAnError(t *testing.T) {
	m, err := realmproto.Decode([]byte(`{"type":"scene.start","scene":"s1"}`), realmproto.FromRealm)
	if err != nil {
		t.Fatalf("Decode(unknown type) err = %v, want nil", err)
	}
	u, ok := m.(*realmproto.Unknown)
	if !ok || u.Name != "scene.start" {
		t.Fatalf("Decode(unknown type) = %#v, want *Unknown{Name: scene.start}", m)
	}
}

func TestUnknownFieldsIgnored(t *testing.T) {
	m, err := realmproto.Decode([]byte(`{"type":"pong","n":5,"later":"field"}`), realmproto.FromRealm)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p, ok := m.(*realmproto.Pong); !ok || p.N != 5 {
		t.Fatalf("Decode = %#v, want *Pong{N: 5}", m)
	}
}

func TestNullGMCPDataMeansNoPayload(t *testing.T) {
	m, err := realmproto.Decode([]byte(`{"type":"gmcp","session":1,"package":"Core.Ping","data":null}`), realmproto.FromRealm)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	g, ok := m.(*realmproto.GMCP)
	if !ok || g.Data != nil {
		t.Fatalf("Decode = %#v, want GMCP with nil Data", m)
	}
}

func TestEncodeValidates(t *testing.T) {
	cases := []realmproto.Message{
		&realmproto.Text{Session: 0, Text: "no session"},
		&realmproto.Hello{Realm: "live"}, // no versions
		&realmproto.Unknown{Name: "x"},
	}
	for _, m := range cases {
		if p, err := realmproto.Encode(m); err == nil {
			t.Errorf("Encode(%#v) = %s, want an error", m, p)
		}
	}
}

// protocol.md §7: only the listed client fields cross the link. MNES
// variables (which may include a client-supplied IPADDRESS) and telnet
// option lists stay in the gateway.
func TestClientFromKeepsOnlyListedFields(t *testing.T) {
	in := session.ClientInfo{
		Name: "mudlet", Version: "5.1.1", Terminal: "ANSI-256COLOR",
		MTTS: 64 | 4 | 1, HasMTTS: true, // screen reader, UTF-8, ANSI
		Charset: "UTF-8", Width: 100, Height: 30,
		Env:     map[string]string{"CLIENT_NAME": "Mudlet", "IPADDRESS": "192.0.2.1"},
		Options: []string{"NAWS"},
	}
	got := realmproto.ClientFrom(in)
	want := realmproto.ClientInfo{
		Name: "mudlet", Version: "5.1.1", Terminal: "ANSI-256COLOR",
		MTTS: intp(69), Charset: "UTF-8", Width: 100, Height: 30, ScreenReader: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ClientFrom = %+v, want %+v", got, want)
	}
	payload, err := realmproto.Encode(&realmproto.Client{Session: 1, Client: got})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if bytes.Contains(payload, []byte("192.0.2.1")) || bytes.Contains(payload, []byte("IPADDRESS")) {
		t.Fatalf("encoded client info leaks MNES variables: %s", payload)
	}
}

func TestClientFromWithoutMTTS(t *testing.T) {
	got := realmproto.ClientFrom(session.ClientInfo{Name: "telnet"})
	if got.MTTS != nil {
		t.Fatalf("ClientFrom(no MTTS).MTTS = %d, want nil (absent on the wire)", *got.MTTS)
	}
}

// ── Conn ─────────────────────────────────────────────────────

func TestPipeCarriesMessagesBothWays(t *testing.T) {
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { gw.Close(); realm.Close() })

	type result struct {
		m   realmproto.Message
		err error
	}
	got := make(chan result, 1)
	go func() {
		m, err := gw.RecvLimit(realmproto.MaxHello)
		got <- result{m, err}
	}()
	hello := &realmproto.Hello{Versions: []int{1}, Realm: "live"}
	if err := realm.Send(hello); err != nil {
		t.Fatalf("realm Send(hello): %v", err)
	}
	select {
	case r := <-got:
		if r.err != nil || !reflect.DeepEqual(r.m, hello) {
			t.Fatalf("gateway Recv = %+v, %v; want %+v", r.m, r.err, hello)
		}
	case <-time.After(timeout):
		t.Fatal("gateway never received hello")
	}

	go func() {
		m, err := realm.Recv()
		got <- result{m, err}
	}()
	welcome := &realmproto.Welcome{Version: 1}
	if err := gw.Send(welcome); err != nil {
		t.Fatalf("gateway Send(welcome): %v", err)
	}
	select {
	case r := <-got:
		if r.err != nil || !reflect.DeepEqual(r.m, welcome) {
			t.Fatalf("realm Recv = %+v, %v; want %+v", r.m, r.err, welcome)
		}
	case <-time.After(timeout):
		t.Fatal("realm never received welcome")
	}
}

func TestCloseUnblocksRecv(t *testing.T) {
	gw, realm := realmproto.Pipe()
	t.Cleanup(func() { realm.Close() })
	done := make(chan error, 1)
	go func() {
		_, err := gw.Recv()
		done <- err
	}()
	if err := realm.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Recv after peer close = %v, want io.EOF", err)
		}
	case <-time.After(timeout):
		t.Fatal("Recv still blocked after the peer closed")
	}
	gw.Close()
}

// A realm that runs session handlers sees the same client the gateway saw,
// minus the fields that never cross the link.
func TestToSessionInvertsClientFrom(t *testing.T) {
	in := session.ClientInfo{
		Name: "mudlet", Version: "5.1.1", Terminal: "ANSI", MTTS: 64 | 1, HasMTTS: true,
		Charset: "UTF-8", Width: 100, Height: 30,
	}
	got := realmproto.ClientFrom(in).ToSession()
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("ClientFrom(c).ToSession() = %+v, want %+v", got, in)
	}
	if !got.ScreenReader() {
		t.Fatal("ToSession lost the MTTS screen-reader bit")
	}
	if none := (realmproto.ClientInfo{Name: "x"}).ToSession(); none.HasMTTS {
		t.Fatalf("ToSession(no mtts).HasMTTS = true, want false")
	}
}

// The spelling rule stops at GMCP data: that is the player's own JSON,
// relayed as is (protocol.md §2).
func TestGMCPDataKeysNotChecked(t *testing.T) {
	m, err := realmproto.Decode([]byte(`{"type":"gmcp","session":1,"package":"Char.Vitals","data":{"HP":1,"HP":2}}`), realmproto.FromRealm)
	if err != nil {
		t.Fatalf("Decode(GMCP with its own odd keys) = %v, want it relayed", err)
	}
	if g, ok := m.(*realmproto.GMCP); !ok || string(g.Data) != `{"HP":1,"HP":2}` {
		t.Fatalf("Decode = %+v, want the data unchanged", m)
	}
}
