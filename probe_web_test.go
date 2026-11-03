package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestActiveWebChecks(t *testing.T) {
	l := newWebLab(t)
	d := l.h.dns

	// app: a sign-in page with most of what can go wrong
	l.host("app.example.test", "203.0.113.40")
	appCert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "app.example.test", "build01.corp") // its default certificate names an internal host
	d.add(t, "good-cdn.test. 60 IN NS ns1.good-cdn.test.")                                   // a registered script host; lapsed-cdn.test is not
	l.serve("203.0.113.40", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "abc", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Path: "/"}) // not a session cookie
			_, _ = fmt.Fprint(w, `<html><head><title>Grafana</title>
				<script src="https://cdn.lapsed-cdn.test/lib.js"></script>
				<script src="//cdn.good-cdn.test/ok.js"></script>
				<script src="https://www.example.test/own.js"></script></head><body>sign in</body></html>`)
		case "/swagger-ui.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<html><div id="swagger-ui"></div><script src="swagger-ui-bundle.js"></script></html>`)
		case "/graphql":
			b, _ := io.ReadAll(r.Body)
			if r.Method == http.MethodPost && strings.Contains(string(b), "__schema") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query"},{"name":"User"}]}}}`)
				return
			}
			http.NotFound(w, r)
		case "/_ignition/health-check":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"can_execute_commands":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "<html><title>NotFound // Werkzeug Debugger</title></html>")
		}
	}), &appCert, tls.VersionTLS12)

	// safe: the same kind of page done right
	l.host("safe.example.test", "203.0.113.41")
	safeCert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "safe.example.test")
	l.serve("203.0.113.41", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Access-Control-Allow-Origin", "https://www.example.test") // a fixed allow-list, not an echo
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "abc", Path: "/", Secure: true, HttpOnly: true})
		_, _ = fmt.Fprint(w, `<html><head><title>Safe</title><script src="https://cdn.good-cdn.test/ok.js"></script></head></html>`)
	}), &safeCert, tls.VersionTLS12)

	// big: a directory listing offering a database dump
	l.host("big.example.test", "203.0.113.43")
	l.serve("203.0.113.43", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<html><head><title>Index of /</title></head><body><h1>Index of /</h1><a href="db-backup.sql">db-backup.sql</a></body></html>`)
	}), nil, 0)

	// MTA-STS: the record exists (cleanMailDNS), the policy file is served but lists no mail server
	d.add(t, "mta-sts.example.test. 60 IN A 203.0.113.42")
	d.addIP(t, "203.0.113.42", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	stsCert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "mta-sts.example.test")
	l.serve("203.0.113.42", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/mta-sts.txt" {
			_, _ = fmt.Fprint(w, "version: STSv1\nmode: enforce\nmax_age: 86400\n")
			return
		}
		http.NotFound(w, r)
	}), &stsCert, tls.VersionTLS12)

	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	if tg2, _ := l.h.store.GetTarget(tg.ID); tg2.LastStatus != "ok" {
		t.Fatalf("scan: %s", tg2.LastError)
	}

	for _, w := range []struct{ kind, host, sev, text string }{
		{"directory-listing", "big.example.test", "high", "db-backup.sql"},
		{"exposed-api-schema", "/swagger-ui.html", "medium", "Swagger UI"},
		{"exposed-api-schema", "/graphql", "medium", "introspection"},
		{"cors-credential-leak", "app.example.test", "high", "easm-cors-check-"},
		{"debug-mode-enabled", "PHP/7.4.3", "low", "X-Powered-By"},
		{"debug-mode-enabled", "Werkzeug", "high", "any missing page"},
		{"debug-mode-enabled", "Ignition", "high", "_ignition/health-check"},
		{"second-order-script-takeover", "lapsed-cdn.test", "high", "not registered"},
		{"insecure-auth-cookie", "app.example.test", "medium", "sessionid (no Secure, no HttpOnly)"},
		{"missing-security-headers", "app.example.test", "medium", "X-Frame-Options"},
		{"tls-sni-hostname-leak", "build01.corp", "low", "203.0.113.40"},
		{"email-auth", "mta-sts.example.test", "medium", "no mx: lines"},
	} {
		f := l.findingFor(w.kind, w.host)
		if f == nil {
			t.Errorf("missing %s for %s; open: %v", w.kind, w.host, l.openKinds())
			continue
		}
		if f.Severity != w.sev || !strings.Contains(f.Detail, w.text) {
			t.Errorf("%s for %s: severity %s, detail %q", w.kind, w.host, f.Severity, f.Detail)
		}
	}
	for _, kind := range []string{"cors-credential-leak", "insecure-auth-cookie", "missing-security-headers", "debug-mode-enabled", "second-order-script-takeover"} {
		if f := l.findingFor(kind, "safe.example.test"); f != nil {
			t.Errorf("safe site: unexpected %s: %s", kind, f.Detail)
		}
	}
	if f := l.findingFor("insecure-auth-cookie", "theme"); f != nil {
		t.Errorf("a preference cookie was reported: %s", f.Detail)
	}
	if f := l.findingFor("second-order-script-takeover", "good-cdn.test"); f != nil {
		t.Errorf("a registered script domain was reported: %s", f.Detail)
	}

	// Switching active checks off must not close what only an active check can see.
	st, _ := l.h.store.LoadSettings()
	st.ActiveChecks = false
	l.h.saveSettings(st)
	l.setProber()
	l.h.scanN(tg.ID, 1)
	for _, kind := range []string{"cors-credential-leak", "login-portal", "directory-listing"} {
		if l.openKinds()[kind] == 0 {
			t.Errorf("%s was closed by a scan without active checks", kind)
		}
	}
}

func TestMTASTSPolicyValidation(t *testing.T) {
	for body, want := range map[string]string{
		"version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 604800\n":     "",
		"version: STSv1\r\nmode: testing\r\nmx: *.example.test\r\nmax_age: 86400\r\n": "",
		"version: STSv1\nmode: none\nmax_age: 86400\n":                                "",
		"<html>Not found</html>":                            "version: STSv1",
		"version: STSv1\nmode: strict\nmx: m\nmax_age: 1\n": "valid mode",
		"version: STSv1\nmode: enforce\nmx: m\n":            "max_age",
		"version: STSv1\nmode: enforce\nmax_age: 86400\n":   "no mx:",
	} {
		if got := validMTASTSPolicy(body); (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%q: got %q, want %q", body, got, want)
		}
	}
}

func TestInternalNames(t *testing.T) {
	for n, want := range map[string]bool{
		"build01.corp": true, "dc1.ad.local": true, "fileserver": true, "app.internal": true,
		"www.example.com": false, "*.cloudfront.net": false, "localhost": false, "10.0.0.1": false, "api.example.co.uk": false,
	} {
		if got := internalName(n); got != want {
			t.Errorf("internalName(%q) = %v", n, got)
		}
	}
}
