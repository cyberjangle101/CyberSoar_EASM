package main

import (
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Light and dark mode. With no choice made the interface follows the operating
// system; the toggle in the top bar stores an explicit choice in a cookie, which the
// server reads so the page arrives in the right colours (no flash, no inline script).

const themeCookie = "easm_theme"

// themeOf returns "light", "dark", or "" (follow the system) for a request.
func themeOf(r *http.Request) string {
	c, err := r.Cookie(themeCookie)
	if err != nil {
		return ""
	}
	switch c.Value {
	case "light", "dark":
		return c.Value
	}
	return ""
}

// initialOf is the letter shown in the account avatar.
func initialOf(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:] // DOMAIN\user → user
	}
	r, _ := utf8.DecodeRuneInString(name)
	if r == utf8.RuneError || !unicode.IsPrint(r) {
		return "?"
	}
	return string(unicode.ToUpper(r))
}

// themeSet stores the chosen theme ("system" clears it, so the page follows the
// operating system again) and returns to the page the choice was made on.
func (s *Server) themeSet(w http.ResponseWriter, r *http.Request, _ *Session) {
	t := r.PostFormValue("theme")
	maxAge := 400 * 24 * 3600
	switch t {
	case "light", "dark":
	case "system":
		t, maxAge = "", -1
	default:
		t = "dark" // the toggle was pressed while following the system; the script normally fills this in
	}
	http.SetCookie(w, &http.Cookie{Name: themeCookie, Value: t, Path: "/", HttpOnly: true, Secure: s.secure, // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- Secure is on whenever the UI is served over TLS; plain-HTTP mode could not send it back
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
	http.Redirect(w, r, safeNext(r.PostFormValue("next"), "/"), http.StatusSeeOther) // nosemgrep: go.lang.security.injection.open-redirect.open-redirect -- safeNext allows only same-site paths
}
