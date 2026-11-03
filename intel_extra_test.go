package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMurmur3(t *testing.T) {
	for in, want := range map[string]int32{"": 0, "hello": 613153351, "The quick brown fox jumps over the lazy dog": 776992547} {
		if got := mmh3([]byte(in)); got != want {
			t.Errorf("mmh3(%q) = %d, want %d", in, got, want)
		}
	}
	// Shodan hashes the base64 text, wrapped at 76 characters with a trailing newline.
	if a, b := faviconHash([]byte("icon")), mmh3([]byte("aWNvbg==\n")); a != b {
		t.Errorf("faviconHash = %d, want %d", a, b)
	}
}

func TestSpamBlocklists(t *testing.T) {
	h := newHarness(t)
	h.seedExample() // mail for example.test goes to mail.example.test (203.0.113.12); the domain is 203.0.113.10
	h.dns.add(t, "12.113.0.203.bl.spamcop.net. 60 IN A 127.0.0.2")
	h.dns.add(t, "10.113.0.203.psbl.surriel.com. 60 IN A 127.0.0.2")
	st, _ := h.store.LoadSettings()
	st.DNSBLEnabled = true
	h.saveSettings(st)
	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	f := openFindingOf(t, h, "example.test", "email-auth", "example.test")
	var bl *Finding
	for _, x := range findingsOf(t, h, "example.test", "email-auth", "open") {
		if strings.HasSuffix(x.Key, ":dnsbl-listed") {
			bl = &x
		}
	}
	_ = f
	if bl == nil || bl.Severity != "high" || !strings.Contains(bl.Detail, "203.0.113.12 (mail address) on SpamCop") || !strings.Contains(bl.Detail, "203.0.113.10 (web address) on PSBL") {
		t.Fatalf("blocklist finding: %+v", bl)
	}
	// delisted: the finding closes
	h.dns.remove("12.113.0.203.bl.spamcop.net.", 1)
	h.dns.remove("10.113.0.203.psbl.surriel.com.", 1)
	h.scan(tg.ID)
	for _, x := range findingsOf(t, h, "example.test", "email-auth", "open") {
		if strings.HasSuffix(x.Key, ":dnsbl-listed") {
			t.Errorf("still open after delisting: %s", x.Detail)
		}
	}
}

func TestDependencyConfusion(t *testing.T) {
	l := newWebLab(t)
	st, _ := l.h.store.LoadSettings()
	st.DependencyConfusion = true
	l.h.saveSettings(st)
	l.setProber()
	l.h.intel.mu.Lock()
	l.h.intel.packages = map[string]bool{"npm/react": true, "npm/lodash": true, "pypi/requests": true}
	l.h.intel.mu.Unlock()

	l.host("app.example.test", "203.0.113.80")
	cert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "app.example.test")
	l.serve("203.0.113.80", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, `<html><head><title>App</title><script src="/static/app.js"></script><script src="https://cdn.other.test/x.js"></script></head></html>`)
		case "/static/app.js":
			_, _ = fmt.Fprint(w, "console.log(1)\n//# sourceMappingURL=app.js.map\n")
		case "/static/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"version":3,"sources":["webpack:///./node_modules/react/index.js","webpack:///./node_modules/acme-internal-utils/lib/a.js","webpack:///./node_modules/@acme/secret-lib/x.js","webpack:///./src/main.js"]}`)
		case "/package.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"dependencies":{"lodash":"^4.17.21","acme-config":"1.0.0","local-thing":"file:../local"}}`)
		case "/requirements.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "requests==2.31.0\nacme-billing-client>=1.2\n# a comment\n")
		default:
			http.NotFound(w, r)
		}
	}), &cert, tls.VersionTLS12)

	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)
	got := map[string]string{}
	for _, f := range findingsOf(t, l.h, "example.test", "dependency-confusion", "open") {
		for _, n := range []string{"acme-internal-utils", "@acme/secret-lib", "acme-config", "acme-billing-client", "react", "lodash", "requests", "local-thing"} {
			if strings.Contains(f.Detail, fmt.Sprintf("%q", n)) {
				got[n] = f.Severity
			}
		}
	}
	want := map[string]string{"acme-internal-utils": "high", "@acme/secret-lib": "medium", "acme-config": "high", "acme-billing-client": "high"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("dependency confusion: got %v, want %v", got, want)
	}
}

func TestLookalikeCertificatesAndClones(t *testing.T) {
	l := newWebLab(t)
	h := l.h
	h.dns.add(t, "example.test. 60 IN NS ns1.example.test.")
	st, _ := h.store.LoadSettings()
	st.LookalikeEnabled, st.LookalikeMax, st.LookalikeProbe = true, 400, true
	h.saveSettings(st)
	l.setProber()

	icon := []byte("\x00\x00\x01\x00 the acme icon")
	site := func(title, extra string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/favicon.ico" {
				w.Header().Set("Content-Type", "image/x-icon")
				_, _ = w.Write(icon)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, "<html><head><title>%s</title></head><body>%s</body></html>", title, extra)
		})
	}
	own := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "example.test", "www.example.test")
	l.serve("203.0.113.10", 443, site("Acme Corporation", "welcome"), &own, tls.VersionTLS12)

	// exmaple.test: a registered look-alike with mail and web, a fresh certificate, and a copy of the site
	h.dns.add(t, "exmaple.test. 60 IN NS ns.evil.test.")
	h.dns.add(t, "exmaple.test. 60 IN MX 10 mx.exmaple.test.")
	h.dns.add(t, "exmaple.test. 60 IN A 203.0.113.99")
	fake := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "exmaple.test")
	l.serve("203.0.113.99", 443, site("Acme Corporation", `<form><input type="password" name="p"></form>`), &fake, tls.VersionTLS12)
	h.src.mu.Lock()
	h.src.serial++
	h.src.crt = append(h.src.crt, crtRow{ID: 9001, IssuerCAID: 77, IssuerName: "C=US, O=Let's Encrypt, CN=R11", CommonName: "exmaple.test", NameValue: "exmaple.test\nwww.exmaple.test",
		NotBefore: time.Now().Add(-24 * time.Hour).UTC().Format("2006-01-02T15:04:05"), NotAfter: time.Now().Add(80 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05"), SerialNumber: "ab01"})
	h.src.mu.Unlock()
	// xample.test: registered, web only, unrelated content and an old certificate
	h.dns.add(t, "xample.test. 60 IN NS ns.other.test.")
	h.dns.add(t, "xample.test. 60 IN A 198.51.100.50")
	l.serve("198.51.100.50", 443, page("Xample bakery", "bread"), &fake, tls.VersionTLS12)

	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	if f := openFindingOf(t, h, "example.test", "lookalike-tls-issued", "exmaple.test"); f == nil || f.Severity != "high" || !strings.Contains(f.Detail, "Let's Encrypt") || !strings.Contains(f.Detail, "crt.sh/?id=9001") {
		t.Errorf("certificate on a look-alike: %+v", f)
	}
	if f := openFindingOf(t, h, "example.test", "lookalike-tls-issued", "xample.test"); f != nil {
		t.Errorf("look-alike without a recent certificate reported: %s", f.Detail)
	}
	f := openFindingOf(t, h, "example.test", "phishing-clone", "exmaple.test")
	if f == nil || f.Severity != "high" || !strings.Contains(f.Detail, "favicon hash") || !strings.Contains(f.Detail, "password field") {
		t.Errorf("clone: %+v", f)
	}
	if f := openFindingOf(t, h, "example.test", "phishing-clone", "xample.test"); f != nil {
		t.Errorf("an unrelated site reported as a clone: %s", f.Detail)
	}
}
