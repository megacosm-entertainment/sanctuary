// Package account holds accounts: who a player is to the gateway, before
// any realm or character (design §05, "Accounts & auth"). Stage 03 builds
// it: password hashing, TOTP and recovery codes, and the account store,
// an interface with a file backend as the zero-dependency default (design
// §03).
package account
