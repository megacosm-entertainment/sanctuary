module sanctuary

// The go line is a security floor, not just a language version: it is the
// oldest toolchain allowed to build the gateway. Raise it to the newest
// patch release whenever govulncheck (scripts/vulncheck.sh) reports a fix.
go 1.27.4

require (
	golang.org/x/crypto v0.59.0
	rsc.io/qr v0.2.0
)

require golang.org/x/sys v0.50.0 // indirect
