package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBrandWords(t *testing.T) {
	got := brandWords("acme.co.uk", []string{" Widget ", "ab", "acme", "has-hyphen", "Gizmo9", "a-b-c", "-bad"})
	if want := []string{"acme", "widget", "hashyphen", "gizmo9"}; !slices.Equal(got, want) {
		t.Errorf("brandWords = %v, want %v", got, want)
	}
	if got := brandWords("abc.com", nil); len(got) != 0 {
		t.Errorf("a three-letter name is too short to watch: %v", got)
	}
	// A hyphenated organisation name is watched, not silently skipped: matched without the
	// hyphen, and searched for in certificate logs under both spellings.
	words, searches := brandTerms("acme-corp.com", nil)
	if !slices.Equal(words, []string{"acmecorp"}) || !slices.Equal(searches, []string{"acmecorp", "acme-corp"}) {
		t.Errorf("brandTerms(acme-corp.com) = %v, %v", words, searches)
	}
	if w, _, ok := brandMatch("acme-corp-login.com", words); !ok || w != "acmecorp" {
		t.Errorf("acme-corp-login.com should match acmecorp")
	}
}

// The scan of a hyphenated domain finds a look-alike that keeps the hyphen.
func TestBrandWatchHyphenatedName(t *testing.T) {
	h := newHarness(t)
	h.dns.add(t, "acme-corp.test. 60 IN A 203.0.113.10")
	h.dns.add(t, "acme-corp.test. 60 IN NS ns1.acme-corp.test.")
	st, _ := h.store.LoadSettings()
	st.LookalikeEnabled, st.LookalikeMax = true, 10
	h.saveSettings(st)
	h.src.addRecentCert("acme-corp-login.test")
	h.dns.add(t, "acme-corp-login.test. 60 IN NS ns.evil.test.")
	h.dns.add(t, "acme-corp-login.test. 60 IN MX 10 mx.acme-corp-login.test.")
	h.dns.add(t, "acme-corp-login.test. 60 IN A 203.0.113.99")
	tg := h.addTarget("acme-corp.test", "")
	h.scan(tg.ID)
	if _, ok := findingKeys(t, h, "lookalike-domain", "open")["lookalike:acme-corp.test:acme-corp-login.test"]; !ok {
		t.Fatal("the hyphenated brand look-alike was not reported")
	}
}

func TestBrandMatch(t *testing.T) {
	words := []string{"acme", "cybersoar"}
	for _, c := range []struct {
		domain string
		typo   bool
		ok     bool
	}{
		{"acme-login-secure.com", false, true},
		{"secureacme.net", false, true},
		{"4cme-pay.co.uk", false, true}, // a digit for a letter
		{"ac-me.shop", false, true},     // a hyphen inside the word
		{"cybersar.com", true, true},    // one letter missing (long words only)
		{"cyber5oar.io", false, true},
		{"acne.com", false, false}, // one letter from a short word: the generated variations cover that
		{"unrelated.com", false, false},
		{"not a domain", false, false},
	} {
		_, typo, ok := brandMatch(c.domain, words)
		if ok != c.ok || typo != c.typo {
			t.Errorf("brandMatch(%q) = typo %v ok %v, want typo %v ok %v", c.domain, typo, ok, c.typo, c.ok)
		}
	}
}

func TestWithinOneEdit(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"cybersoar", "cybersoar", true}, {"cybersar", "cybersoar", true}, {"cybersoarr", "cybersoar", true},
		{"cybersoaz", "cybersoar", true}, {"cybresoar", "cybersoar", false}, {"cyber", "cybersoar", false}, {"", "a", true},
	} {
		if got := withinOneEdit(c.a, c.b); got != c.want {
			t.Errorf("withinOneEdit(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestParseBrandCerts(t *testing.T) {
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	body := `[{"name_value":"acme-login.com\nwww.acme-login.com","not_before":"2026-10-20T08:00:00"},
		{"name_value":"old-acme.com","not_before":"2026-01-01T00:00:00"},
		{"name_value":"acme-login.com","not_before":"2026-10-21T00:00:00"}]`
	got, err := parseBrandCerts(strings.NewReader(body), since)
	if err != nil || !slices.Equal(got, []string{"acme-login.com", "www.acme-login.com"}) {
		t.Errorf("parseBrandCerts = %v, %v", got, err)
	}
}

func TestParseNRD(t *testing.T) {
	plain := "# newly registered\nacme-pay.com\n\nOTHER.NET,2026-11-07\n"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = io.WriteString(zw, plain)
	_ = zw.Close()
	var zb bytes.Buffer
	za := zip.NewWriter(&zb)
	fw, _ := za.Create("domain-names.txt")
	_, _ = io.WriteString(fw, plain)
	_ = za.Close()
	for name, body := range map[string][]byte{"plain": []byte(plain), "gzip": gz.Bytes(), "zip": zb.Bytes()} {
		got, err := parseNRD(body)
		if err != nil || !slices.Equal(got, []string{"acme-pay.com", "other.net"}) {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
	if _, err := parseNRD([]byte("# nothing\n")); err == nil {
		t.Error("an empty feed should be an error")
	}
}

// The feed is fetched over HTTPS with the key as X-API-Key, then served from memory.
func TestNRDFeedCache(t *testing.T) {
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-API-Key") != "k123" {
			http.Error(w, "no key", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "acme-pay.com\n")
	}))
	t.Cleanup(srv.Close)
	f := NewFeeds(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), NewHealthBoard())
	f.nrd.hc = srv.Client()
	for i := 0; i < 2; i++ {
		got, err := f.NRD(testCtx(t), srv.URL+"/nrd.txt", "k123")
		if err != nil || !slices.Equal(got, []string{"acme-pay.com"}) {
			t.Fatalf("NRD: %v, %v", got, err)
		}
	}
	if calls != 1 {
		t.Errorf("the feed was downloaded %d times; the second call should use the cached copy", calls)
	}
	if _, err := f.NRD(testCtx(t), "http://feed.test/nrd.txt", ""); err == nil {
		t.Error("a plain-HTTP feed address should be refused")
	}
}

// A scan with the look-alike check on reports a domain that contains the brand name and has a
// fresh certificate, and leaves out old certificates, parked names and the target's own.
func TestBrandWatchScan(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.dns.add(t, "example.test. 60 IN NS ns1.example.test.")
	st, _ := h.store.LoadSettings()
	st.LookalikeEnabled, st.LookalikeMax = true, 10
	h.saveSettings(st)

	h.src.addRecentCert("example-login.test", "www.example-login.test") // reported: mail and web
	h.dns.add(t, "example-login.test. 60 IN NS ns.evil.test.")
	h.dns.add(t, "example-login.test. 60 IN MX 10 mx.example-login.test.")
	h.dns.add(t, "example-login.test. 60 IN A 203.0.113.99")
	h.src.addCert("example-old.test") // a certificate from January: outside the 30-day window
	h.dns.add(t, "example-old.test. 60 IN NS ns.evil.test.")
	h.dns.add(t, "example-old.test. 60 IN A 203.0.113.98")
	h.src.addRecentCert("example-parked.test") // parked: not reported
	h.dns.add(t, "example-parked.test. 60 IN NS ns1.afternic.com.")
	h.dns.add(t, "example-parked.test. 60 IN A 198.51.100.60")

	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)

	open := findingKeys(t, h, "lookalike-domain", "open")
	f, ok := open["lookalike:example.test:example-login.test"]
	if !ok {
		t.Fatalf("the brand look-alike was not reported; got %v", fkeys(open))
	}
	if f.Severity != "medium" || !strings.Contains(f.Detail, brandKindCTWord) {
		t.Errorf("finding: %+v", f)
	}
	for k := range open {
		if strings.Contains(k, "example-old.test") || strings.Contains(k, "example-parked.test") {
			t.Errorf("should not be reported: %s", k)
		}
	}
}
