module sanctuary

// The go line is a security floor, not just a language version: it is the
// oldest toolchain allowed to build the gateway. Raise it to the newest
// patch release whenever govulncheck (scripts/vulncheck.sh) reports a fix.
go 1.27.4
