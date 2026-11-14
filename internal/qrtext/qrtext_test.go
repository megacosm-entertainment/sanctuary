package qrtext

import (
	"strings"
	"testing"
)

const uri = "otpauth://totp/Sanctuary:Mara?algorithm=SHA1&digits=6&issuer=Sanctuary&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func encode(t *testing.T) *Code {
	t.Helper()
	c, err := Encode(uri)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// check compares a drawing read back as a grid with the code, border
// included.
func check(t *testing.T, c *Code, grid [][]bool) {
	t.Helper()
	n := c.Size() + 2*Quiet
	if len(grid) < n {
		t.Fatalf("%d rows, want %d", len(grid), n)
	}
	for y := 0; y < n; y++ {
		if len(grid[y]) != n {
			t.Fatalf("row %d has %d modules, want %d", y, len(grid[y]), n)
		}
		for x := 0; x < n; x++ {
			if grid[y][x] != c.black(x-Quiet, y-Quiet) {
				t.Fatalf("module (%d,%d) drawn %v, code has %v", x-Quiet, y-Quiet, grid[y][x], !grid[y][x])
			}
		}
	}
	// The border is white: a scanner needs it.
	for x := 0; x < n; x++ {
		if grid[0][x] || grid[n-1][x] || grid[x][0] || grid[x][n-1] {
			t.Fatal("border not white")
		}
	}
}

func TestHalfBlocks(t *testing.T) {
	c := encode(t)
	out := c.HalfBlocks()
	var grid [][]bool
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(line, on) || !strings.HasSuffix(line, off) {
			t.Fatalf("line %q is not wrapped in black-on-white", line)
		}
		var top, bottom []bool
		for _, r := range strings.TrimSuffix(strings.TrimPrefix(line, on), off) {
			switch r {
			case '█':
				top, bottom = append(top, true), append(bottom, true)
			case '▀':
				top, bottom = append(top, true), append(bottom, false)
			case '▄':
				top, bottom = append(top, false), append(bottom, true)
			case ' ':
				top, bottom = append(top, false), append(bottom, false)
			default:
				t.Fatalf("unexpected %q", r)
			}
		}
		grid = append(grid, top, bottom)
	}
	check(t, c, grid)
	if w := len([]rune(strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(out, "\n", 2)[0], on), off))); w != c.HalfBlocksWidth() {
		t.Fatalf("width %d, HalfBlocksWidth %d", w, c.HalfBlocksWidth())
	}
	if c.HalfBlocksWidth() > 80 {
		t.Fatalf("a set-up link needs %d columns; want it within 80", c.HalfBlocksWidth())
	}
}

func TestSpaces(t *testing.T) {
	c := encode(t)
	out := c.Spaces()
	if strings.ContainsFunc(out, func(r rune) bool { return r > 0x7e }) {
		t.Fatal("Spaces is not plain ASCII")
	}
	var grid [][]bool
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var row []bool
		black := false
		for len(line) > 0 {
			switch {
			case strings.HasPrefix(line, "\x1b[40m"):
				black, line = true, line[5:]
			case strings.HasPrefix(line, "\x1b[47m"):
				black, line = false, line[5:]
			case strings.HasPrefix(line, off):
				line = line[len(off):]
			case strings.HasPrefix(line, "  "):
				row, line = append(row, black), line[2:]
			default:
				t.Fatalf("unexpected %q", line)
			}
		}
		grid = append(grid, row)
	}
	check(t, c, grid)
	if c.SpacesWidth() != 2*c.HalfBlocksWidth() {
		t.Fatal("SpacesWidth is not twice HalfBlocksWidth")
	}
}
