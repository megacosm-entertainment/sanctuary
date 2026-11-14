package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"sanctuary/internal/account"
	"sanctuary/internal/cli"
	"sanctuary/internal/sanitize"
)

const accountUsage = `usage: sanctuary-gateway account [settings] COMMAND [options] [args]

Staff commands on the gateway's accounts. They read the same settings as
the gateway (flags, SANCTUARY_ environment, -config file), so DATA_DIR and
the reserved names match, and they are safe while the gateway runs.

  list                         every account, with roles and state
  show NAME                    one account (never its password or secrets)
  create [-role R]... [-allow-reserved] NAME
                               new account with a temporary password,
                               changed at first login
  reset [-totp] NAME           new temporary password; -totp also removes
                               the authenticator and recovery codes
  invite [-expires D] [-by N]  an invite code (for SIGNUP=invite)
  role NAME [+ROLE|-ROLE]...   add or remove roles; with none, show them
  disable NAME REASON...       refuse logins; the reason is for staff only
  enable NAME                  allow logins again

A change takes effect at the account's next login: a player already
connected stays connected.
`

// runAccount is the account command; it returns the exit status.
func runAccount(args []string, env func(string) (string, bool), stdout, stderr io.Writer) int {
	s, o := declare()
	if err := s.Parse(args, env); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, accountUsage)
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}
	rest := s.Flags().Args()
	if len(rest) == 0 || rest[0] == "help" {
		fmt.Fprint(stdout, accountUsage)
		if len(rest) == 0 {
			return 2
		}
		return 0
	}
	store, err := openStore(o)
	if err != nil {
		fmt.Fprintln(stderr, "account:", err)
		return 1
	}
	c := &staff{store: store, o: o, out: stdout, ctx: context.Background()}
	cmd, cargs := rest[0], rest[1:]
	run, ok := map[string]func([]string) error{
		"list":    c.list,
		"show":    c.show,
		"create":  c.create,
		"reset":   c.reset,
		"invite":  c.invite,
		"role":    c.role,
		"disable": c.disable,
		"enable":  c.enable,
	}[cmd]
	if !ok {
		fmt.Fprintf(stderr, "account: unknown command %q\n\n%s", cmd, accountUsage)
		return 2
	}
	if err := run(cargs); err != nil {
		var u usageError
		if errors.As(err, &u) {
			fmt.Fprintf(stderr, "account %s: %v\n", cmd, err)
			return 2
		}
		fmt.Fprintf(stderr, "account %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

type usageError string

func (e usageError) Error() string { return string(e) }

// openStore opens the account store with the server's name policy.
func openStore(o settings) (*account.FileStore, error) {
	names, err := account.NewNames(cli.SplitList(*o.reserved), *o.reservedOnly)
	if err != nil {
		return nil, err
	}
	store, err := account.OpenFileStore(*o.dataDir)
	if err != nil {
		return nil, err
	}
	store.Names = names
	return store, nil
}

type staff struct {
	store *account.FileStore
	o     settings
	out   io.Writer
	ctx   context.Context
}

// flags parses a command's options; positional arguments may come before
// or after them.
func flags(name string, args []string, define func(*flag.FlagSet)) ([]string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if define != nil {
		define(fs)
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageError(err.Error())
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos, args = append(pos, args[0]), args[1:]
	}
}

func exactly(n int, pos []string, what string) error {
	if len(pos) != n {
		return usageError("want " + what)
	}
	return nil
}

// get reads an account, with a message naming it when it does not exist.
func (c *staff) get(name string) (*account.Account, error) {
	a, err := c.store.Get(c.ctx, name)
	if errors.Is(err, account.ErrNotFound) {
		return nil, fmt.Errorf("no account called %q", sanitize.Untrusted(name))
	}
	return a, err
}

// change reads, edits and writes an account, retrying when the running
// gateway wrote it in between.
func (c *staff) change(name string, edit func(*account.Account) error) (*account.Account, error) {
	for i := 0; ; i++ {
		a, err := c.get(name)
		if err != nil {
			return nil, err
		}
		if err := edit(a); err != nil {
			return nil, err
		}
		err = c.store.Update(c.ctx, a)
		if !errors.Is(err, account.ErrConflict) || i == 3 {
			return a, err
		}
	}
}

// state is an account's flags, for list and show.
func state(a *account.Account) string {
	var s []string
	if len(a.Roles) > 0 {
		s = append(s, strings.Join(a.Roles, "+"))
	}
	if a.TOTP != nil {
		s = append(s, "2fa")
	}
	if a.MustChangePassword {
		s = append(s, "must-change-password")
	}
	if a.Disabled != "" {
		s = append(s, "disabled")
	}
	return strings.Join(s, " ")
}

func (c *staff) list(args []string) error {
	pos, err := flags("list", args, nil)
	if err != nil {
		return err
	}
	if err := exactly(0, pos, "no arguments"); err != nil {
		return err
	}
	all, err := c.store.List(c.ctx)
	if err != nil {
		return err
	}
	for _, a := range all {
		fmt.Fprintf(c.out, "%-20s %s\n", a.Name, state(a))
	}
	fmt.Fprintf(c.out, "%d account(s)\n", len(all))
	return nil
}

func day(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04 MST")
}

func (c *staff) show(args []string) error {
	pos, err := flags("show", args, nil)
	if err != nil {
		return err
	}
	if err := exactly(1, pos, "an account name"); err != nil {
		return err
	}
	a, err := c.get(pos[0])
	if err != nil {
		return err
	}
	w := c.out
	fmt.Fprintf(w, "Name:              %s\n", a.Name)
	fmt.Fprintf(w, "ID:                %s\n", a.ID)
	fmt.Fprintf(w, "Created:           %s\n", day(a.Created))
	fmt.Fprintf(w, "Password changed:  %s\n", day(a.PasswordChanged))
	if a.MustChangePassword {
		fmt.Fprintln(w, "                   (must be changed at next login)")
	}
	if a.TOTP != nil {
		fmt.Fprintf(w, "Authenticator:     since %s, %d recovery code(s) left\n", day(a.TOTP.Enabled), len(a.Recovery))
	} else {
		fmt.Fprintln(w, "Authenticator:     none")
	}
	fmt.Fprintf(w, "Roles:             %s\n", orNone(strings.Join(a.Roles, ", ")))
	if a.Email != "" {
		fmt.Fprintf(w, "Email:             %s (unverified)\n", sanitize.Untrusted(a.Email))
	}
	if a.Disabled != "" {
		fmt.Fprintf(w, "Disabled:          %s\n", sanitize.Untrusted(a.Disabled))
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// roles is a repeatable -role flag.
type roles []string

func (r *roles) String() string     { return strings.Join(*r, ",") }
func (r *roles) Set(v string) error { *r = append(*r, v); return nil }

// checkRole: roles are short lowercase words, so a typo is an error
// rather than a role nobody checks for.
func checkRole(r string) error {
	if r == "" || len(r) > 20 || strings.Trim(r, "abcdefghijklmnopqrstuvwxyz") != "" {
		return usageError(fmt.Sprintf("role %q: roles are 1-20 lowercase letters", sanitize.Untrusted(r)))
	}
	return nil
}

func addRole(a *account.Account, r string) {
	if !a.HasRole(r) {
		a.Roles = append(a.Roles, r)
	}
}

// temporary makes a temporary password and its hash.
func (c *staff) temporary() (string, string, error) {
	pw, err := account.NewTemporaryPassword()
	if err != nil {
		return "", "", err
	}
	hash, err := account.NewHasher(account.DefaultParams, 1).Hash(c.ctx, pw)
	return pw, hash, err
}

func (c *staff) create(args []string) error {
	var rs roles
	var allowReserved bool
	pos, err := flags("create", args, func(fs *flag.FlagSet) {
		fs.Var(&rs, "role", "give the account this role (repeatable)")
		fs.BoolVar(&allowReserved, "allow-reserved", false, "allow a reserved name, e.g. for a staff account")
	})
	if err != nil {
		return err
	}
	if err := exactly(1, pos, "an account name"); err != nil {
		return err
	}
	for _, r := range rs {
		if err := checkRole(r); err != nil {
			return err
		}
	}
	if allowReserved {
		// The prompt's own words stay reserved even so.
		c.store.Names, _ = account.NewNames(nil, true)
	}
	pw, hash, err := c.temporary()
	if err != nil {
		return err
	}
	id, err := account.NewID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	a := &account.Account{ID: id, Name: pos[0], Created: now, Password: hash, PasswordChanged: now, MustChangePassword: true}
	for _, r := range rs {
		addRole(a, r)
	}
	switch err := c.store.Create(c.ctx, a); {
	case errors.Is(err, account.ErrReservedName):
		return fmt.Errorf("%q is reserved; use -allow-reserved if you mean it", pos[0])
	case err != nil:
		return err
	}
	fmt.Fprintf(c.out, "Created %s%s.\nTemporary password: %s\nGive it to the player privately; they choose their own at first login. It is not stored and is shown only now.\n",
		a.Name, roleNote(a.Roles), pw)
	return nil
}

func roleNote(rs []string) string {
	if len(rs) == 0 {
		return ""
	}
	return " (" + strings.Join(rs, ", ") + ")"
}

func (c *staff) reset(args []string) error {
	var totp bool
	pos, err := flags("reset", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&totp, "totp", false, "also remove the authenticator and recovery codes (a lost device)")
	})
	if err != nil {
		return err
	}
	if err := exactly(1, pos, "an account name"); err != nil {
		return err
	}
	pw, hash, err := c.temporary()
	if err != nil {
		return err
	}
	a, err := c.change(pos[0], func(a *account.Account) error {
		a.Password, a.PasswordChanged, a.MustChangePassword = hash, time.Now().UTC(), true
		if totp {
			a.TOTP, a.Recovery = nil, nil
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Reset %s.\nTemporary password: %s\n", a.Name, pw)
	if totp {
		fmt.Fprintln(c.out, "The authenticator and recovery codes are removed; the player can set up a new one.")
	} else if a.TOTP != nil {
		fmt.Fprintln(c.out, "The authenticator is still required (reset -totp removes it).")
	}
	return nil
}

func (c *staff) invite(args []string) error {
	expires := 7 * 24 * time.Hour
	by := "staff"
	pos, err := flags("invite", args, func(fs *flag.FlagSet) {
		fs.DurationVar(&expires, "expires", expires, "how long the code is valid")
		fs.StringVar(&by, "by", by, "who it is from, recorded with the invite")
	})
	if err != nil {
		return err
	}
	if err := exactly(0, pos, "no arguments"); err != nil {
		return err
	}
	if expires <= 0 {
		return usageError("-expires must be positive")
	}
	code, err := account.NewInviteCode()
	if err != nil {
		return err
	}
	until := time.Now().Add(expires)
	if err := c.store.AddInvite(c.ctx, code, by, until); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Invite code: %s\nValid until %s, for one account.\n", code, day(until))
	if signup := strings.ToLower(*c.o.signup); signup != "invite" {
		fmt.Fprintf(c.out, "Note: SIGNUP is %q here, so the login prompt does not ask for invite codes.\n", signup)
	}
	return nil
}

func (c *staff) role(args []string) error {
	if len(args) == 0 {
		return usageError("want an account name, then +ROLE or -ROLE")
	}
	name, changes := args[0], args[1:]
	for _, ch := range changes {
		if len(ch) < 2 || (ch[0] != '+' && ch[0] != '-') {
			return usageError(fmt.Sprintf("%q: write +ROLE to add or -ROLE to remove", sanitize.Untrusted(ch)))
		}
		if err := checkRole(ch[1:]); err != nil {
			return err
		}
	}
	var a *account.Account
	var err error
	if len(changes) == 0 {
		a, err = c.get(name)
	} else {
		a, err = c.change(name, func(a *account.Account) error {
			for _, ch := range changes {
				r := ch[1:]
				if ch[0] == '+' {
					addRole(a, r)
					continue
				}
				kept := a.Roles[:0]
				for _, x := range a.Roles {
					if x != r {
						kept = append(kept, x)
					}
				}
				a.Roles = kept
			}
			return nil
		})
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s: %s\n", a.Name, orNone(strings.Join(a.Roles, ", ")))
	return nil
}

func (c *staff) disable(args []string) error {
	if len(args) < 2 {
		return usageError("want an account name and a reason")
	}
	reason := strings.TrimSpace(strings.Join(args[1:], " "))
	if reason == "" {
		return usageError("want a reason")
	}
	a, err := c.change(args[0], func(a *account.Account) error {
		a.Disabled = reason
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Disabled %s. Logins are refused from now on; if they are connected, they stay connected until they leave.\n", a.Name)
	return nil
}

func (c *staff) enable(args []string) error {
	pos, err := flags("enable", args, nil)
	if err != nil {
		return err
	}
	if err := exactly(1, pos, "an account name"); err != nil {
		return err
	}
	a, err := c.change(pos[0], func(a *account.Account) error {
		a.Disabled = ""
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Enabled %s.\n", a.Name)
	return nil
}
