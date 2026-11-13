// Package telnet implements the gateway's telnet transport: an RFC 1143
// ("Q method") option negotiator, line assembly, and the MUD protocol
// options adopted in the design doc's §04 client-standards table.
package telnet

import "strconv"

// Telnet commands.
const (
	SE   byte = 240
	NOP  byte = 241
	DM   byte = 242
	BRK  byte = 243
	IP   byte = 244
	AO   byte = 245
	AYT  byte = 246
	EC   byte = 247
	EL   byte = 248
	GA   byte = 249
	SB   byte = 250
	WILL byte = 251
	WONT byte = 252
	DO   byte = 253
	DONT byte = 254
	IAC  byte = 255
	EOR  byte = 239 // the EOR command (RFC 885), sent after prompts
)

// Telnet options.
const (
	OptEcho       byte = 1
	OptSGA        byte = 3
	OptTTYPE      byte = 24
	OptEOR        byte = 25
	OptNAWS       byte = 31
	OptNewEnviron byte = 39 // carries MNES
	OptCharset    byte = 42
	OptMSSP       byte = 70
	OptMCCP2      byte = 86
	OptGMCP       byte = 201
)

// OptionName returns a readable name for logs and diagnostics.
func OptionName(o byte) string {
	switch o {
	case OptEcho:
		return "ECHO"
	case OptSGA:
		return "SGA"
	case OptTTYPE:
		return "TTYPE"
	case OptEOR:
		return "EOR"
	case OptNAWS:
		return "NAWS"
	case OptNewEnviron:
		return "NEW-ENVIRON"
	case OptCharset:
		return "CHARSET"
	case OptMSSP:
		return "MSSP"
	case OptMCCP2:
		return "MCCP2"
	case OptGMCP:
		return "GMCP"
	}
	return "opt" + strconv.Itoa(int(o))
}

// Subnegotiation codes, exported for test clients.
const (
	// TTYPE (RFC 1091).
	TTypeIs   byte = 0
	TTypeSend byte = 1

	// NEW-ENVIRON (RFC 1572), which carries MNES.
	EnvIs      byte = 0
	EnvSend    byte = 1
	EnvInfo    byte = 2
	EnvVar     byte = 0
	EnvVal     byte = 1
	EnvEsc     byte = 2
	EnvUserVar byte = 3

	// CHARSET (RFC 2066).
	CharsetRequest  byte = 1
	CharsetAccepted byte = 2
	CharsetRejected byte = 3

	// MSSP variable and value markers.
	MSSPVarCode byte = 1
	MSSPValCode byte = 2
)
