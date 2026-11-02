package main

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestTwoFactorAfterLockout: guessing two-factor codes blocks sign-in, and the page says so with
// how long. Once a block has run out the counter is still high, so one slip blocks it again; that
// slip must say so too, not "wait for the next code", or the next right code looks broken.
func TestTwoFactorAfterLockout(t *testing.T) {
	e := newWebEnv(t)
	hash, _ := hashPassword("correct horse battery")
	id, _ := e.store.CreateUser("lou", hash, RoleViewer)
	secret, _ := newTOTPSecret()
	if err := e.store.SetTOTP(id, secret, "", true); err != nil {
		t.Fatal(err)
	}
	ticketRe := regexp.MustCompile(`name="ticket" value="([^"]+)"`)
	start := func() (*browser, string, string, string) {
		nb := e.browser()
		pre := nb.loginPre("/login")
		_, body, _ := nb.postRaw("/login", url.Values{"csrf": {pre}, "username": {"lou"}, "password": {"correct horse battery"}})
		if tk := ticketRe.FindStringSubmatch(body); tk != nil {
			return nb, pre, tk[1], body
		}
		return nb, pre, "", body
	}
	code := func(nb *browser, pre, tk, c string) (int, string) {
		st, body, _ := nb.postRaw("/login/2fa", url.Values{"csrf": {pre}, "ticket": {tk}, "code": {c}})
		return st, body
	}
	expire := func() {
		e.web.mu.Lock()
		for _, f := range e.web.fails {
			f.blocked = time.Now().Add(-time.Second)
		}
		e.web.mu.Unlock()
	}
	blocked := regexp.MustCompile(`sign-in is blocked for \d+ minutes?`)

	nb, pre, tk, _ := start()
	var body string
	for i := 1; i <= maxFails; i++ {
		_, body = code(nb, pre, tk, "000000")
		if i < maxFails && !strings.Contains(body, "not accepted") {
			t.Fatalf("guess %d: no wrong-code message", i)
		}
	}
	if !blocked.MatchString(body) || ticketRe.MatchString(body) {
		t.Fatal("the guess that set off the block did not say so")
	}
	if _, _, tk, body = start(); tk != "" || !blocked.MatchString(body) {
		t.Fatal("password step not blocked, or no time given")
	}

	expire()
	nb, pre, tk, _ = start()
	if tk == "" {
		t.Fatal("no two-factor prompt after the block ran out")
	}
	if _, body = code(nb, pre, tk, "000000"); !blocked.MatchString(body) || strings.Contains(body, "Wait for the next code") {
		t.Fatal("a slip after the block blocked again without saying so")
	}

	expire()
	nb, pre, tk, _ = start()
	if st, _ := code(nb, pre, tk, codeNow(t, secret)); st != 303 {
		t.Fatalf("right code refused once the block ran out: %d", st)
	}
}

func TestBlockedMessage(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Second:                  "blocked for 1 minute.",
		time.Minute:                  "blocked for 1 minute.",
		time.Minute + time.Second:    "blocked for 2 minutes.",
		30 * time.Minute:             "blocked for 30 minutes.",
		16*time.Minute - time.Second: "blocked for 16 minutes.",
	} {
		if got := blockedMessage(d); !strings.Contains(got, want) {
			t.Errorf("%v: %q", d, got)
		}
	}
}
