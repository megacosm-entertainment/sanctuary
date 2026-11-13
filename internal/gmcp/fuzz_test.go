package gmcp

import (
	"encoding/json"
	"testing"
)

// FuzzParse checks Parse on arbitrary input: it never panics, anything it
// accepts has a valid package name and valid JSON, and formatting an
// accepted message parses back to the same thing.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`Core.Hello {"client":"Mudlet","version":"5.1.1"}`))
	f.Add([]byte(`Core.Supports.Set ["Char 1"]`))
	f.Add([]byte(`Core.Ping`))
	f.Add([]byte(`Bad Name {`))
	f.Fuzz(func(t *testing.T, in []byte) {
		pkg, data, err := Parse(in)
		if err != nil {
			return
		}
		if !validPackage([]byte(pkg)) {
			t.Fatalf("accepted invalid package %q", pkg)
		}
		if data != nil && !json.Valid(data) {
			t.Fatalf("accepted invalid JSON %q", data)
		}
		out, err := Format(pkg, data)
		if err != nil {
			t.Fatalf("Format of an accepted message failed: %v", err)
		}
		pkg2, data2, err := Parse(out)
		if err != nil || pkg2 != pkg {
			t.Fatalf("round trip of %q: %q, %v", out, pkg2, err)
		}
		if (data == nil) != (data2 == nil) {
			t.Fatalf("round trip changed payload presence: %q -> %q", data, data2)
		}
	})
}
