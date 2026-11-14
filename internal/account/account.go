package account

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Schema is the version of the stored account record. A record names the
// version that wrote it, so a later engine can read older ones (design
// §05, "Schema versioning").
const Schema = 1

// Account is one player's account: identity and authentication, scoped to
// the gateway (the "data center", design §06), never to a realm.
// Characters belong to realms and are not stored here.
type Account struct {
	Schema   int       `json:"schema"`
	ID       string    `json:"id"`   // random, stable for the account's life
	Name     string    `json:"name"` // as the player chose it; unique ignoring case
	Created  time.Time `json:"created"`
	Revision int64     `json:"revision"` // bumped on every write; see Store.Update

	Password        string    `json:"password"` // Argon2id, PHC format
	PasswordChanged time.Time `json:"password_changed"`
	// MustChangePassword is set when staff reset a password: the next
	// login must choose a new one.
	MustChangePassword bool `json:"must_change_password,omitempty"`

	TOTP     *TOTPState `json:"totp,omitempty"`
	Recovery []string   `json:"recovery,omitempty"` // hashes of unused recovery codes

	Roles []string `json:"roles,omitempty"` // "staff", "admin"
	// Email is unverified until the notification service exists; it is
	// never shown to anyone but the account's owner and staff.
	Email string `json:"email,omitempty"`
	// Disabled, when set, is why logins are refused.
	Disabled string `json:"disabled,omitempty"`
}

// TOTPState is an enrolled authenticator.
type TOTPState struct {
	Sealed   string    `json:"sealed"`    // the secret, sealed with the SecretKey
	LastStep int64     `json:"last_step"` // last accepted step: no replays
	Enabled  time.Time `json:"enabled"`
}

// HasRole reports whether the account has role r.
func (a *Account) HasRole(r string) bool {
	for _, x := range a.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// NewID returns a fresh account id.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ── Names ───────────────────────────────────────────────────

const (
	MinName = 3
	MaxName = 20
)

// promptWords are words the login prompt itself understands. They are
// always reserved: an account called "new" would make signing up
// impossible to tell from logging in.
var promptWords = []string{"new", "quit", "help"}

// DefaultReserved are the built-in reserved names: roles and system names
// a player might hope to be mistaken for. A server can add its own (staff
// characters, deities, place names) or replace this list; see NewNames.
var DefaultReserved = []string{"admin", "administrator", "staff", "system", "sanctuary", "gateway", "realm"}

// Names is the policy for new account names: the character rules, and the
// names that are reserved.
type Names struct {
	reserved map[string]bool
}

// NewNames builds a policy from the server's extra reserved names, merged
// with DefaultReserved, or instead of it when replace is set. The prompt
// words are reserved either way. Each extra must itself be a well-formed
// name (letters and digits), so a typo in the setting is reported rather
// than silently reserving nothing.
func NewNames(extra []string, replace bool) (Names, error) {
	n := Names{reserved: map[string]bool{}}
	for _, w := range promptWords {
		n.reserved[w] = true
	}
	if !replace {
		for _, w := range DefaultReserved {
			n.reserved[w] = true
		}
	}
	for _, w := range extra {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		if err := checkChars(w); err != nil {
			return Names{}, fmt.Errorf("account: reserved name %q: %w", w, err)
		}
		n.reserved[Key(w)] = true
	}
	return n, nil
}

// DefaultNames is the policy with no server additions.
var DefaultNames, _ = NewNames(nil, false)

// Reserved reports whether name is reserved under this policy.
func (n Names) Reserved(name string) bool {
	if n.reserved == nil {
		return DefaultNames.Reserved(name)
	}
	return n.reserved[Key(name)]
}

// ErrBadName reports an unacceptable account name.
var ErrBadName = fmt.Errorf("account: a name is %d-%d letters and digits, starting with a letter", MinName, MaxName)

// ErrReservedName reports a name kept for the system.
var ErrReservedName = errors.New("account: that name is reserved")

// Check validates a new account name. Names are ASCII letters and digits
// only: no lookalike characters (homoglyphs), no spaces, nothing a screen
// reader would read oddly.
func (n Names) Check(name string) error {
	if err := checkChars(name); err != nil {
		return err
	}
	if n.Reserved(name) {
		return ErrReservedName
	}
	return nil
}

// CheckName validates a name under DefaultNames.
func CheckName(name string) error { return DefaultNames.Check(name) }

func checkChars(name string) error {
	if len(name) < MinName || len(name) > MaxName {
		return ErrBadName
	}
	for i, c := range []byte(name) {
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !(letter || (i > 0 && c >= '0' && c <= '9')) {
			return ErrBadName
		}
	}
	return nil
}

// Key is the case-insensitive form names are unique by.
func Key(name string) string { return strings.ToLower(name) }

// ── Store ───────────────────────────────────────────────────

// Errors from a Store.
var (
	ErrNotFound      = errors.New("account: no such account")
	ErrExists        = errors.New("account: that name is taken")
	ErrConflict      = errors.New("account: changed by someone else since it was read; read it again")
	ErrInviteInvalid = errors.New("account: that invite code is not valid")
)

// Store keeps accounts and invites. It is an infrastructure boundary
// (design §03): the file store is the zero-dependency default, and a
// database backend implements the same interface.
type Store interface {
	// Get returns the account with this name (any case), or ErrNotFound.
	Get(ctx context.Context, name string) (*Account, error)
	// Create stores a new account, or ErrExists if the name is taken.
	Create(ctx context.Context, a *Account) error
	// CreateWithInvite redeems an invite and creates the account as one
	// step: neither happens without the other.
	CreateWithInvite(ctx context.Context, a *Account, code string) error
	// Update writes a, which must have been read at its current revision;
	// otherwise ErrConflict and nothing is written. On success a.Revision
	// is the new revision.
	Update(ctx context.Context, a *Account) error
	// List returns every account, sorted by name ignoring case.
	List(ctx context.Context) ([]*Account, error)
	// AddInvite stores an invite, kept only as a hash, valid until expires.
	AddInvite(ctx context.Context, code, by string, expires time.Time) error
}
