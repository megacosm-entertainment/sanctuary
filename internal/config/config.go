// Package config reads a program's operational settings (ports, addresses,
// trust, limits) from built-in defaults, an env-format config file, the
// environment and command-line flags, in that order of precedence: a later
// source wins.
//
// Each setting is declared once. Its flag, environment variable and file
// key all derive from the declaration: setting TELNET is the flag -telnet,
// the variable SANCTUARY_TELNET, and the file line SANCTUARY_TELNET=:9000.
// The file format is the env-file format, so one file works with -config,
// docker --env-file, compose env_file, a Kubernetes ConfigMap, and
// `doppler run` / `doppler secrets download --format env`.
//
// Secret settings (private keys, and later passwords and tokens) never take
// a literal value from a config file or a flag: a file may be committed and
// a flag shows in `ps`. They take content only from the environment
// (SANCTUARY_REALM_KEY, as a secrets manager injects it) and otherwise a
// path (SANCTUARY_REALM_KEY_FILE, or the flag), as secret mounts provide.
package config

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Prefix starts every environment variable and file key.
const Prefix = "SANCTUARY_"

// Source says where a setting's value came from.
type Source string

const (
	FromDefault Source = "default"
	FromFile    Source = "file"
	FromEnv     Source = "env"
	FromFlag    Source = "flag"
)

type kind int

const (
	kindString kind = iota
	kindInt
	kindBool
	kindDuration
	kindBlob // content or a path to it; see Blob
)

type setting struct {
	name   string // TELNET
	help   string
	def    string
	kind   kind
	secret bool

	raw    string // current value as text (for blobs: content or path)
	isPath bool   // blobs: raw is a path
	from   Source

	str *string
	num *int
	on  *bool
	dur *time.Duration
}

// Set is one program's settings.
type Set struct {
	prog     string
	fs       *flag.FlagSet
	settings []*setting
	byName   map[string]*setting
	config   *string // -config path
	warnings []string
}

// New starts an empty set for prog. Declare settings, then call Parse.
func New(prog string) *Set {
	s := &Set{prog: prog, fs: flag.NewFlagSet(prog, flag.ContinueOnError), byName: map[string]*setting{}}
	s.config = s.fs.String("config", "", "settings file in env format (also "+Prefix+"CONFIG)")
	return s
}

// Flags exposes the flag set for flags that are actions rather than
// settings (-gen-identity), which have no environment or file form.
func (s *Set) Flags() *flag.FlagSet { return s.fs }

func flagName(name string) string { return strings.ReplaceAll(strings.ToLower(name), "_", "-") }

func (s *Set) add(st *setting) *setting {
	if _, dup := s.byName[st.name]; dup {
		panic("config: setting declared twice: " + st.name)
	}
	if st.name == "CONFIG" || strings.HasSuffix(st.name, "_FILE") {
		panic("config: reserved setting name: " + st.name)
	}
	st.raw, st.from = st.def, FromDefault
	s.settings = append(s.settings, st)
	s.byName[st.name] = st
	return st
}

// String declares a text setting.
func (s *Set) String(name, def, help string) *string {
	v := def
	st := s.add(&setting{name: name, def: def, help: help, kind: kindString, str: &v})
	s.fs.Func(flagName(name), help+" (env "+Prefix+name+")", func(x string) error { return s.set(st, x, FromFlag) })
	if def != "" {
		s.fs.Lookup(flagName(name)).DefValue = def
	}
	return &v
}

// Int declares an integer setting.
func (s *Set) Int(name string, def int, help string) *int {
	v := def
	st := s.add(&setting{name: name, def: strconv.Itoa(def), help: help, kind: kindInt, num: &v})
	s.fs.Func(flagName(name), help+" (env "+Prefix+name+")", func(x string) error { return s.set(st, x, FromFlag) })
	s.fs.Lookup(flagName(name)).DefValue = st.def
	return &v
}

// Bool declares an on/off setting. On the command line -name and
// -name=false both work.
func (s *Set) Bool(name string, def bool, help string) *bool {
	v := def
	st := s.add(&setting{name: name, def: strconv.FormatBool(def), help: help, kind: kindBool, on: &v})
	s.fs.BoolFunc(flagName(name), help+" (env "+Prefix+name+")", func(x string) error { return s.set(st, x, FromFlag) })
	s.fs.Lookup(flagName(name)).DefValue = st.def
	return &v
}

// Duration declares a duration setting ("30s", "2m").
func (s *Set) Duration(name string, def time.Duration, help string) *time.Duration {
	v := def
	st := s.add(&setting{name: name, def: def.String(), help: help, kind: kindDuration, dur: &v})
	s.fs.Func(flagName(name), help+" (env "+Prefix+name+")", func(x string) error { return s.set(st, x, FromFlag) })
	s.fs.Lookup(flagName(name)).DefValue = st.def
	return &v
}

// Blob is a setting whose value is file content, such as a certificate or
// key. It can be given as content (NAME) or as a path (NAME_FILE, or the
// flag). For a secret blob, content is accepted only from the environment.
type Blob struct{ st *setting }

// Blob declares a content-or-path setting.
func (s *Set) Blob(name string, secret bool, help string) Blob {
	st := s.add(&setting{name: name, help: help, kind: kindBlob, secret: secret})
	where := "env " + Prefix + name + "_FILE (path)"
	if secret {
		where += " or " + Prefix + name + " (content, environment only)"
	} else {
		where += " or " + Prefix + name + " (content)"
	}
	s.fs.Func(flagName(name), help+": path ("+where+")", func(x string) error {
		st.raw, st.isPath, st.from = x, true, FromFlag
		return nil
	})
	return Blob{st}
}

// Set reports whether the blob was given at all.
func (b Blob) Set() bool { return b.st.raw != "" }

// Bytes returns the content, reading the file if a path was given.
func (b Blob) Bytes() ([]byte, error) {
	if !b.st.isPath {
		return []byte(b.st.raw), nil
	}
	data, err := os.ReadFile(b.st.raw)
	if err != nil {
		var pe *os.PathError
		if b.st.secret && errors.As(err, &pe) {
			// Report why, not where: the "path" may be a pasted secret.
			return nil, fmt.Errorf("config: %s: cannot read the file given: %w", b.st.name, pe.Err)
		}
		return nil, fmt.Errorf("config: %s: %w", b.st.name, err)
	}
	return data, nil
}

func (s *Set) set(st *setting, x string, from Source) error {
	switch st.kind {
	case kindString:
		*st.str = x
	case kindInt:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return fmt.Errorf("%s: %q is not a whole number", st.name, x)
		}
		*st.num = n
	case kindBool:
		b, err := strconv.ParseBool(strings.TrimSpace(x))
		if err != nil {
			return fmt.Errorf("%s: %q is not true or false", st.name, x)
		}
		*st.on = b
	case kindDuration:
		d, err := time.ParseDuration(strings.TrimSpace(x))
		if err != nil {
			return fmt.Errorf("%s: %q is not a duration such as 30s", st.name, x)
		}
		*st.dur = d
	case kindBlob:
		st.isPath = false
	}
	st.raw, st.from = x, from
	return nil
}

// Parse reads, in order of increasing precedence, the config file (-config
// or SANCTUARY_CONFIG), the environment, and args. env is os.LookupEnv in
// production; tests pass a map.
func (s *Set) Parse(args []string, env func(string) (string, bool)) error {
	s.fs.SetOutput(io.Discard)
	if err := s.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%s: %w", s.prog, err)
	}
	byFlag := map[string]bool{}
	s.fs.Visit(func(f *flag.Flag) { byFlag[f.Name] = true })

	path := *s.config
	if path == "" {
		path, _ = env(Prefix + "CONFIG")
	}
	var file map[string]string
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		file, err = ParseEnvFile(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("config: %s: %w", path, err)
		}
		s.checkFileKeys(path, file)
	}

	for _, st := range s.settings {
		if byFlag[flagName(st.name)] {
			continue
		}
		if err := s.resolve(st, file, env); err != nil {
			return err
		}
	}
	for _, st := range s.settings {
		if st.kind == kindBlob && st.secret && st.isPath && looksLikeContent(st.raw) {
			return fmt.Errorf("config: %s: the value given as a path looks like the secret itself; give a path (-%s or %s%s_FILE), or the content in the environment as %s%s. The value is not shown", st.name, flagName(st.name), Prefix, st.name, Prefix, st.name)
		}
	}
	return nil
}

// resolve applies env over file for one setting not given as a flag.
func (s *Set) resolve(st *setting, file map[string]string, env func(string) (string, bool)) error {
	key := Prefix + st.name
	if st.kind == kindBlob {
		if v, ok := env(key); ok && v != "" {
			st.raw, st.isPath, st.from = v, false, FromEnv
			return nil
		}
		if v, ok := env(key + "_FILE"); ok && v != "" {
			st.raw, st.isPath, st.from = v, true, FromEnv
			return nil
		}
		if v, ok := file[key]; ok && v != "" {
			if st.secret {
				return fmt.Errorf("config: %s is a secret and cannot be given in a config file; set %s_FILE to a path, or provide %s through the environment (a secrets manager)", key, key, key)
			}
			st.raw, st.isPath, st.from = v, false, FromFile
			return nil
		}
		if v, ok := file[key+"_FILE"]; ok && v != "" {
			st.raw, st.isPath, st.from = v, true, FromFile
		}
		return nil
	}
	if v, ok := env(key); ok {
		return s.set(st, v, FromEnv)
	}
	if v, ok := file[key]; ok {
		return s.set(st, v, FromFile)
	}
	return nil
}

// checkFileKeys warns about keys that match no setting. A warning, not an
// error: one file may be shared by programs with different settings.
func (s *Set) checkFileKeys(path string, file map[string]string) {
	var unknown []string
	for k := range file {
		name, ok := strings.CutPrefix(k, Prefix)
		if !ok {
			continue // not ours; a shared file may hold other programs' variables
		}
		base := strings.TrimSuffix(name, "_FILE")
		if st, known := s.byName[base]; known && (base == name || st.kind == kindBlob) {
			continue
		}
		if name == "CONFIG" {
			continue
		}
		unknown = append(unknown, k)
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		s.warnings = append(s.warnings, fmt.Sprintf("%s: %s is not a %s setting (typo, or meant for another program?)", path, k, s.prog))
	}
}

// Warnings are problems worth logging that do not stop the program.
func (s *Set) Warnings() []string { return s.warnings }

// Entry describes one setting's effective value, for the startup log.
type Entry struct {
	Name   string
	Value  string // "[secret]" for secret content; paths are shown
	Source Source
}

// Effective lists every setting with its value and where it came from.
// Secret content is never included.
func (s *Set) Effective() []Entry {
	out := make([]Entry, 0, len(s.settings))
	for _, st := range s.settings {
		v := st.raw
		switch {
		case st.kind == kindBlob && st.raw == "":
			v = ""
		case st.kind == kindBlob && st.isPath && st.secret:
			// Not even the path: if someone pasted the secret where the
			// path goes, this is where it would leak (RT-3-3).
			v = "[file]"
		case st.kind == kindBlob && st.isPath:
			v = "file " + st.raw
		case st.kind == kindBlob && st.secret:
			v = "[secret]"
		case st.kind == kindBlob:
			v = fmt.Sprintf("[%d bytes]", len(st.raw))
		}
		out = append(out, Entry{Name: st.name, Value: v, Source: st.from})
	}
	return out
}

// Usage writes help for every setting, with its flag, variable and default.
func (s *Set) Usage(w io.Writer) {
	fmt.Fprintf(w, "Usage of %s. Settings come from defaults, then a config file (-config or %sCONFIG),\nthen the environment, then flags; a later source wins.\n\n", s.prog, Prefix)
	s.fs.SetOutput(w)
	s.fs.PrintDefaults()
}

// ParseEnvFile reads env-format lines: KEY=VALUE, '#' comments, blank
// lines, an optional "export " prefix, and values optionally in double
// quotes (with \" \\ \n escapes) or single quotes (literal), as written by
// `doppler secrets download --format env` and accepted by compose.
func ParseEnvFile(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20) // a PEM key in a value fits
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || strings.ContainsAny(key, " \t\"'") {
			return nil, fmt.Errorf("line %d: want KEY=VALUE", n)
		}
		val = strings.TrimSpace(val)
		// A double-quoted value may run over several lines, as Doppler's
		// --format env writes certificates and compose accepts: keep
		// reading until the line that closes the quote.
		start := n
		for strings.HasPrefix(val, `"`) && !closesQuote(val) {
			if !sc.Scan() {
				return nil, fmt.Errorf("line %d (%s): unterminated quote", start, key)
			}
			n++
			val += "\n" + strings.TrimRight(sc.Text(), " \t\r")
		}
		v, err := unquote(val)
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", start, key, err)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: %s set twice", n, key)
		}
		out[key] = v
	}
	return out, sc.Err()
}

func unquote(v string) (string, error) {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1], nil
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		var b strings.Builder
		in := v[1 : len(v)-1]
		for i := 0; i < len(in); i++ {
			c := in[i]
			if c != '\\' {
				if c == '"' {
					return "", errors.New("unescaped quote inside a double-quoted value")
				}
				b.WriteByte(c)
				continue
			}
			i++
			if i == len(in) {
				return "", errors.New("value ends with a backslash")
			}
			switch in[i] {
			case 'n':
				b.WriteByte('\n')
			case '"', '\\', '$':
				b.WriteByte(in[i])
			default:
				b.WriteByte('\\')
				b.WriteByte(in[i])
			}
		}
		return b.String(), nil
	}
	if strings.ContainsAny(v, "\"'") && (v[0] == '"' || v[0] == '\'') {
		return "", errors.New("unterminated quote")
	}
	// An unquoted value ends at an inline comment.
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v, nil
}

// closesQuote reports whether a value that starts with a double quote also
// ends with an unescaped one (so it is complete on this line).
func closesQuote(v string) bool {
	if len(v) < 2 || v[len(v)-1] != '"' {
		return false
	}
	// Count the backslashes before the final quote: an odd number escapes it.
	bs := 0
	for i := len(v) - 2; i >= 1 && v[i] == '\\'; i-- {
		bs++
	}
	return bs%2 == 0
}

// looksLikeContent reports whether a "path" is really file content: a PEM
// block or anything with a line break, which no sensible path contains.
func looksLikeContent(s string) bool {
	return strings.Contains(s, "-----BEGIN") || strings.ContainsAny(s, "\r\n")
}
