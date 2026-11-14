package main

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"sanctuary/internal/account"
)

// staffRun runs `sanctuary-gateway account ARGS` against dir, with env as
// the whole environment.
func staffRun(t *testing.T, dir string, env map[string]string, args ...string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	code := runAccount(append([]string{"-data-dir", dir}, args...), lookup, &out, &errOut)
	return out.String(), errOut.String(), code
}

func mustRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, errOut, code := staffRun(t, dir, nil, args...)
	if code != 0 {
		t.Fatalf("account %v: exit %d, %s", args, code, errOut)
	}
	return out
}

var tempPassword = regexp.MustCompile(`Temporary password: ([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})`)

func stored(t *testing.T, dir, name string) *account.Account {
	t.Helper()
	s, err := account.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Get(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func verifies(t *testing.T, hash, pw string) bool {
	t.Helper()
	ok, err := account.NewHasher(account.DefaultParams, 1).Verify(context.Background(), hash, pw)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestAccountCreateAndReset(t *testing.T) {
	dir := t.TempDir()
	out := mustRun(t, dir, "create", "-role", "staff", "Mara")
	m := tempPassword.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no temporary password in %q", out)
	}
	a := stored(t, dir, "mara")
	if !a.MustChangePassword || !a.HasRole("staff") || !verifies(t, a.Password, m[1]) {
		t.Fatalf("created %+v: want must-change, staff, and the printed password", a)
	}
	if strings.Contains(out, a.Password) {
		t.Fatal("the hash was printed")
	}
	if _, errOut, code := staffRun(t, dir, nil, "create", "mara"); code == 0 || !strings.Contains(errOut, "taken") {
		t.Fatalf("second create: exit %d, %q; want taken", code, errOut)
	}

	// A reset gives a new password, and -totp removes the authenticator.
	s, _ := account.OpenFileStore(dir)
	a.TOTP, a.Recovery, a.MustChangePassword = &account.TOTPState{Sealed: "x"}, []string{"h"}, false
	if err := s.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	out = mustRun(t, dir, "reset", "Mara")
	contains(t, out, "still required")
	b := stored(t, dir, "Mara")
	m2 := tempPassword.FindStringSubmatch(out)
	if m2 == nil || verifies(t, b.Password, m[1]) || !verifies(t, b.Password, m2[1]) || !b.MustChangePassword || b.TOTP == nil {
		t.Fatalf("after reset: want the new password only, must-change, TOTP kept")
	}
	mustRun(t, dir, "reset", "-totp", "Mara")
	if c := stored(t, dir, "Mara"); c.TOTP != nil || c.Recovery != nil {
		t.Fatal("reset -totp left the authenticator")
	}
}

func contains(t *testing.T, s, want string) {
	t.Helper()
	if !strings.Contains(s, want) {
		t.Fatalf("%q does not contain %q", s, want)
	}
}

func TestAccountReservedNames(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"SANCTUARY_RESERVED_NAMES": "Thoth"}
	for _, name := range []string{"admin", "Thoth"} {
		if _, errOut, code := staffRun(t, dir, env, "create", name); code == 0 || !strings.Contains(errOut, "reserved") {
			t.Fatalf("create %s: exit %d, %q; want reserved", name, code, errOut)
		}
	}
	for _, name := range []string{"Thoth", "admin"} {
		if _, errOut, code := staffRun(t, dir, env, "create", "-allow-reserved", name); code != 0 {
			t.Fatalf("create -allow-reserved %s: %s", name, errOut)
		}
	}
	// The prompt's own words never.
	if _, _, code := staffRun(t, dir, env, "create", "-allow-reserved", "new"); code == 0 {
		t.Fatal("created an account called new")
	}
}

func TestAccountRolesAndDisable(t *testing.T) {
	dir := t.TempDir()
	mustRun(t, dir, "create", "Kit")
	if out := mustRun(t, dir, "role", "Kit", "+staff", "+admin", "+staff"); out != "Kit: staff, admin\n" {
		t.Fatalf("roles = %q, want staff and admin once each", out)
	}
	contains(t, mustRun(t, dir, "role", "Kit", "-staff"), "Kit: admin")
	contains(t, mustRun(t, dir, "role", "kit"), "Kit: admin")
	if _, _, code := staffRun(t, dir, nil, "role", "Kit", "+Staff!"); code != 2 {
		t.Fatalf("bad role accepted (exit %d)", code)
	}
	if _, _, code := staffRun(t, dir, nil, "role", "Kit", "staff"); code != 2 {
		t.Fatalf("role without + or - accepted (exit %d)", code)
	}

	mustRun(t, dir, "disable", "Kit", "spam", "in", "OOC")
	if a := stored(t, dir, "Kit"); a.Disabled != "spam in OOC" {
		t.Fatalf("disabled = %q", a.Disabled)
	}
	contains(t, mustRun(t, dir, "list"), "disabled")
	contains(t, mustRun(t, dir, "show", "Kit"), "Disabled:          spam in OOC")
	mustRun(t, dir, "enable", "Kit")
	if a := stored(t, dir, "Kit"); a.Disabled != "" {
		t.Fatal("still disabled")
	}
	if _, errOut, code := staffRun(t, dir, nil, "disable", "Nobody", "x"); code != 1 || !strings.Contains(errOut, "no account") {
		t.Fatalf("disable unknown: exit %d, %q", code, errOut)
	}
}

func TestAccountInvite(t *testing.T) {
	dir := t.TempDir()
	out := mustRun(t, dir, "invite", "-expires", "1h", "-by", "Mara")
	m := regexp.MustCompile(`Invite code: (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no code in %q", out)
	}
	contains(t, out, `SIGNUP is "open"`)
	s, _ := account.OpenFileStore(dir)
	if err := s.CreateWithInvite(context.Background(), &account.Account{ID: "i1", Name: "Ned"}, m[1]); err != nil {
		t.Fatalf("redeeming the printed code: %v", err)
	}
	if strings.Contains(mustRun(t, dir, "-signup", "invite", "invite"), "SIGNUP is") {
		t.Fatal("warned about SIGNUP when it is invite")
	}
}

func TestAccountListAndShowKeepSecretsOut(t *testing.T) {
	dir := t.TempDir()
	mustRun(t, dir, "create", "Ola")
	a := stored(t, dir, "Ola")
	for _, out := range []string{mustRun(t, dir, "list"), mustRun(t, dir, "show", "ola")} {
		contains(t, out, "Ola")
		if strings.Contains(out, a.Password) || strings.Contains(out, "argon2") {
			t.Fatalf("a password hash in %q", out)
		}
	}
	contains(t, mustRun(t, dir, "list"), "1 account(s)")
}

func TestAccountUsage(t *testing.T) {
	dir := t.TempDir()
	if out, _, code := staffRun(t, dir, nil); code != 2 || !strings.Contains(out, "usage:") {
		t.Fatalf("no command: exit %d", code)
	}
	if _, errOut, code := staffRun(t, dir, nil, "frobnicate"); code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown command: exit %d", code)
	}
	if _, _, code := staffRun(t, dir, nil, "show"); code != 2 {
		t.Fatalf("show without a name: exit %d", code)
	}
}
