package gmcp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantPkg  string
		wantData string
		wantErr  error
	}{
		{"object payload (Mudlet Core.Hello)", `Core.Hello {"client":"Mudlet","version":"5.1.1"}`, "Core.Hello", `{"client":"Mudlet","version":"5.1.1"}`, nil},
		{"no payload", `Core.Ping`, "Core.Ping", "", nil},
		{"array payload", `Core.Supports.Set ["Char 1", "Room 1"]`, "Core.Supports.Set", `["Char 1", "Room 1"]`, nil},
		{"scalar payload", `Char.Vitals 42`, "Char.Vitals", `42`, nil},
		{"truncated JSON", `Core.Hello {"client":`, "", "", ErrInvalidJSON},
		{"unquoted keys", `Core.Hello {not json}`, "", "", ErrInvalidJSON},
		{"trailing garbage", `Core.Hello {} trailing`, "", "", ErrInvalidJSON},
		{"space in package name", `Core Hello`, "", "", ErrInvalidJSON},
		{"empty", ``, "", "", ErrEmpty},
		{"ESC in package name", "Bad\x1bName {}", "", "", ErrBadPackage},
		{"backslash in package name", `Bad\Name {}`, "", "", ErrBadPackage},
		{"package name over 64 bytes", strings.Repeat("a", 65), "", "", ErrBadPackage},
		{"message over MaxPayload", "A " + `"` + strings.Repeat("x", MaxPayload) + `"`, "", "", ErrTooLarge},
		{"message of exactly MaxPayload", "A " + `"` + strings.Repeat("x", MaxPayload-4) + `"`, "A", `"` + strings.Repeat("x", MaxPayload-4) + `"`, nil},
		{"payload whitespace trimmed", "Core.Hello   {}  ", "Core.Hello", "{}", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, data, err := Parse([]byte(tt.in))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Parse error = %v, want %v", err, tt.wantErr)
			}
			if pkg != tt.wantPkg || string(data) != tt.wantData {
				t.Fatalf("Parse = %q %q, want %q %q", pkg, data, tt.wantPkg, tt.wantData)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	t.Run("payload compacted", func(t *testing.T) {
		const want = `Char.Vitals {"hp":1}`
		if got, err := Format("Char.Vitals", []byte(`{ "hp" : 1 }`)); err != nil || string(got) != want {
			t.Fatalf("Format = %q, %v; want %q, nil", got, err, want)
		}
	})
	t.Run("no payload", func(t *testing.T) {
		if got, err := Format("Core.Ping", nil); err != nil || string(got) != "Core.Ping" {
			t.Fatalf("Format = %q, %v; want \"Core.Ping\", nil", got, err)
		}
	})
	t.Run("invalid package refused", func(t *testing.T) {
		if _, err := Format("Bad Name", nil); !errors.Is(err, ErrBadPackage) {
			t.Fatalf("Format error = %v, want ErrBadPackage", err)
		}
	})
	t.Run("invalid payload refused", func(t *testing.T) {
		if _, err := Format("Char.Vitals", []byte(`{`)); !errors.Is(err, ErrInvalidJSON) {
			t.Fatalf("Format error = %v, want ErrInvalidJSON", err)
		}
	})
}

// The returned payload must not alias the caller's buffer: transports reuse
// their read buffers.
func TestParseCopiesPayload(t *testing.T) {
	buf := []byte(`Core.Hello {"a":1}`)
	_, data, err := Parse(buf)
	if err != nil {
		t.Fatal(err)
	}
	copy(buf, bytes.Repeat([]byte("X"), len(buf)))
	if string(data) != `{"a":1}` {
		t.Fatalf("payload changed to %q after the input buffer was reused", data)
	}
}
