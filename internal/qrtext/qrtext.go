// Package qrtext draws QR codes as terminal text, for scanning off a MUD
// client's screen (TOTP set-up). The encoding is rsc.io/qr's: the standard
// library has none (docs/coding.md §3).
//
// Codes are drawn black on white with explicit colours, whatever the
// client's theme, with a white border (quiet zone), which scanners need.
package qrtext

import (
	"strings"

	"rsc.io/qr"
)

// Quiet is the white border, in modules. The standard asks for four; two
// scan reliably from a screen and keep the code inside 80 columns.
const Quiet = 2

// Code is an encoded QR code.
type Code struct{ c *qr.Code }

// Encode encodes text at error-correction level M, a margin for screens
// that are glary or slightly out of focus.
func Encode(text string) (*Code, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	return &Code{c}, nil
}

// Size is the code's side in modules, without the border.
func (c *Code) Size() int { return c.c.Size }

// black reports a module, the border included (outside the code is white).
func (c *Code) black(x, y int) bool {
	if x < 0 || y < 0 || x >= c.c.Size || y >= c.c.Size {
		return false
	}
	return c.c.Black(x, y)
}

const (
	on  = "\x1b[30;47m" // black on white
	off = "\x1b[0m"
)

// HalfBlocks draws two rows of modules per line with Unicode half blocks,
// one column per module. It needs a client that has claimed UTF-8.
func (c *Code) HalfBlocks() string {
	var b strings.Builder
	for y := -Quiet; y < c.c.Size+Quiet; y += 2 {
		b.WriteString(on)
		for x := -Quiet; x < c.c.Size+Quiet; x++ {
			switch top, bottom := c.black(x, y), c.black(x, y+1); {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString(off + "\n")
	}
	return b.String()
}

// HalfBlocksWidth is the columns HalfBlocks needs.
func (c *Code) HalfBlocksWidth() int { return c.c.Size + 2*Quiet }

// Spaces draws each module as two spaces with a black or white background:
// plain ASCII, for clients without UTF-8, at twice the width.
func (c *Code) Spaces() string {
	const black, white = "\x1b[40m  ", "\x1b[47m  "
	var b strings.Builder
	for y := -Quiet; y < c.c.Size+Quiet; y++ {
		last := ""
		for x := -Quiet; x < c.c.Size+Quiet; x++ {
			cell := white
			if c.black(x, y) {
				cell = black
			}
			if cell != last {
				b.WriteString(cell[:5])
				last = cell
			}
			b.WriteString("  ")
		}
		b.WriteString(off + "\n")
	}
	return b.String()
}

// SpacesWidth is the columns Spaces needs.
func (c *Code) SpacesWidth() int { return 2 * (c.c.Size + 2*Quiet) }
