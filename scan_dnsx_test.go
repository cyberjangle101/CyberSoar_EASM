package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// findingsOf returns a domain's findings of one kind with a status ("" = any).
func findingsOf(t *testing.T, h *harness, root, kind, status string) []Finding {
	t.Helper()
	all, err := h.store.ListFindings(root, status)
	if err != nil {
		t.Fatal(err)
	}
	var out []Finding
	for _, f := range all {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// openFindingOf returns the open finding of a kind on a host, or nil.
func openFindingOf(t *testing.T, h *harness, root, kind, host string) *Finding {
	t.Helper()
	for _, f := range findingsOf(t, h, root, kind, "open") {
		if f.Host == host {
			return &f
		}
	}
	return nil
}

func TestDanglingNSAndMX(t *testing.T) {
	h := newHarness(t)
	d := h.dns
	for _, rr := range []string{
		"acme.test. 60 IN A 203.0.113.10",
		"acme.test. 60 IN NS ns1.acme.test.",
		"acme.test. 60 IN MX 10 mx.lapsed-mail.test.",
		"acme.test. 60 IN MX 20 old.acme.test.",
		"ns1.acme.test. 60 IN A 203.0.113.53",
		// lame: delegated to Route 53, which no longer holds the zone
		"lame.acme.test. 60 IN NS ns-1.awsdns-01.com.",
		"ns-1.awsdns-01.com. 60 IN A 205.251.192.1",
		"awsdns-01.com. 60 IN NS ns.awsdns-01.com.",
		// lapsed: the nameservers' domain does not exist
		"gone.acme.test. 60 IN NS ns1.expired-dns.test.",
		// healthy delegation
		"ok.acme.test. 60 IN NS ns1.good-dns.test.",
		"ns1.good-dns.test. 60 IN A 198.51.100.53",
		"good-dns.test. 60 IN NS ns1.good-dns.test.",
	} {
		d.add(t, rr)
	}
	d.mu.Lock()
	d.refuseSOA = map[string]bool{"lame.acme.test.": true}
	d.mu.Unlock()
	h.src.addCert("acme.test", "lame.acme.test", "gone.acme.test", "ok.acme.test")
	tg := h.addTarget("acme.test", "")
	h.scan(tg.ID)

	if f := openFindingOf(t, h, "acme.test", "dangling-ns", "lame.acme.test"); f == nil || f.Severity != "high" || !strings.Contains(f.Detail, "REFUSED") || !strings.Contains(f.Detail, "Amazon Route 53") {
		t.Errorf("lame delegation not reported: %+v", f)
	}
	if f := openFindingOf(t, h, "acme.test", "dangling-ns", "gone.acme.test"); f == nil || f.Severity != "high" || !strings.Contains(f.Detail, "expired-dns.test, which is not registered") {
		t.Errorf("lapsed nameserver domain not reported: %+v", f)
	}
	if f := openFindingOf(t, h, "acme.test", "dangling-ns", "ok.acme.test"); f != nil {
		t.Errorf("healthy delegation reported: %+v", f)
	}
	if f := openFindingOf(t, h, "acme.test", "dangling-ns", "acme.test"); f != nil {
		t.Errorf("the domain's own nameservers reported: %+v", f)
	}
	mx := findingsOf(t, h, "acme.test", "dangling-mx", "")
	sevs := map[string]string{}
	for _, f := range mx {
		for _, n := range []string{"mx.lapsed-mail.test", "old.acme.test"} {
			if strings.Contains(f.Detail, "goes to "+n) {
				sevs[n] = f.Severity
			}
		}
	}
	if sevs["mx.lapsed-mail.test"] != "high" || sevs["old.acme.test"] != "low" || len(mx) != 2 {
		t.Errorf("dangling MX: %v (%d findings)", sevs, len(mx))
	}

	// fixed: the zone is served again and the mail records are cleaned up, so the findings close
	d.mu.Lock()
	d.refuseSOA = nil
	d.mu.Unlock()
	d.add(t, "expired-dns.test. 60 IN NS ns1.expired-dns.test.")
	d.add(t, "ns1.expired-dns.test. 60 IN A 198.51.100.54")
	d.remove("acme.test.", 15) // MX
	d.add(t, "acme.test. 60 IN MX 10 ns1.acme.test.")
	h.scan(tg.ID)
	for _, host := range []string{"lame.acme.test", "gone.acme.test"} {
		if f := openFindingOf(t, h, "acme.test", "dangling-ns", host); f != nil {
			t.Errorf("%s still open after the fix: %+v", host, f)
		}
	}
	if f := openFindingOf(t, h, "acme.test", "dangling-mx", "acme.test"); f != nil {
		t.Errorf("dangling MX still open after the fix: %+v", f)
	}
}

// A nameserver domain that is registered but withdrawn from DNS (RDAP knows it) is Medium.
func TestDanglingNSOnHold(t *testing.T) {
	h := newHarness(t)
	h.dns.add(t, "acme.test. 60 IN A 203.0.113.10")
	h.dns.add(t, "held.acme.test. 60 IN NS ns1.held-dns.test.")
	h.intel.rdap["held-dns.test"] = rdapBody(time.Now().Add(-5 * 24 * time.Hour))
	h.src.addCert("acme.test", "held.acme.test")
	tg := h.addTarget("acme.test", "")
	h.scan(tg.ID)
	if f := openFindingOf(t, h, "acme.test", "dangling-ns", "held.acme.test"); f == nil || f.Severity != "medium" || !strings.Contains(f.Detail, "expired or on hold") {
		t.Errorf("held nameserver domain: %+v", f)
	}
}

func TestWildcardFinding(t *testing.T) {
	h := newHarness(t)
	h.dns.add(t, "wild.test. 60 IN A 203.0.113.10")
	h.dns.add(t, "*.wild.test. 60 IN A 203.0.113.99")
	h.src.addCert("wild.test", "www.wild.test")
	tg := h.addTarget("wild.test", "")
	h.scan(tg.ID)
	if f := openFindingOf(t, h, "wild.test", "dns-wildcard", "wild.test"); f == nil || f.Severity != "low" || !strings.Contains(f.Detail, "203.0.113.99") {
		t.Fatalf("wildcard not reported: %+v", f)
	}
	h.dns.remove("*.wild.test.", 1)
	h.scan(tg.ID)
	if f := openFindingOf(t, h, "wild.test", "dns-wildcard", "wild.test"); f != nil {
		t.Errorf("wildcard finding still open after the record went: %+v", f)
	}
}

func TestDomainUnlocked(t *testing.T) {
	for _, tc := range []struct {
		domain, status string
		want           bool
	}{
		{"open.test", `"active"`, true},
		{"locked.test", `"active","client transfer prohibited"`, false},
		{"registry.test", `"server transfer prohibited"`, false},
		{"country.uk", `"active"`, false}, // ccTLD: many registries do not use these statuses
	} {
		t.Run(tc.domain, func(t *testing.T) {
			h := newHarness(t)
			h.dns.add(t, tc.domain+". 60 IN A 203.0.113.10")
			h.intel.rdap[tc.domain] = strings.Replace(rdapBody(time.Now().Add(300*24*time.Hour)), `"active","client transfer prohibited"`, tc.status, 1)
			h.src.addCert(tc.domain)
			tg := h.addTarget(tc.domain, "")
			h.scan(tg.ID)
			f := openFindingOf(t, h, tc.domain, "domain-unlocked", tc.domain)
			if (f != nil) != tc.want {
				t.Fatalf("want finding=%v, got %+v", tc.want, f)
			}
			if f != nil && (f.Severity != "medium" || !strings.Contains(f.Detail, "Example Registrar Inc")) {
				t.Errorf("finding: %+v", f)
			}
		})
	}
}

func TestUnauthorizedCertificateAuthority(t *testing.T) {
	h := newHarness(t)
	h.dns.add(t, "acme.test. 60 IN A 203.0.113.10")
	h.dns.add(t, `acme.test. 60 IN CAA 0 issue "letsencrypt.org"`)
	h.dns.add(t, `acme.test. 60 IN CAA 0 issuewild ";"`)
	h.dns.add(t, `shop.acme.test. 60 IN CAA 0 issue "digicert.com"`) // its own CAA allows DigiCert
	h.dns.add(t, "shop.acme.test. 60 IN A 203.0.113.10")
	h.dns.add(t, "www.acme.test. 60 IN A 203.0.113.10")
	recent := time.Now().Add(-48 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	old := time.Now().Add(-90 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	until := time.Now().Add(60 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	add := func(issuer, notBefore string, names ...string) {
		h.src.mu.Lock()
		h.src.serial++
		h.src.crt = append(h.src.crt, crtRow{ID: int64(2000 + h.src.serial), IssuerCAID: int64(h.src.serial), IssuerName: issuer, CommonName: names[0],
			NameValue: strings.Join(names, "\n"), NotBefore: notBefore, NotAfter: until, SerialNumber: fmt.Sprintf("%040x", 500+h.src.serial)})
		h.src.mu.Unlock()
	}
	add("C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1", recent, "www.acme.test") // not allowed: reported
	add("C=US, O=Let's Encrypt, CN=R11", recent, "www.acme.test")                                       // allowed
	add("C=US, O=Let's Encrypt, CN=R11", recent, "*.acme.test")                                         // issuewild forbids every CA: reported
	add("C=US, O=DigiCert Inc, CN=DigiCert TLS", recent, "shop.acme.test")                              // allowed by shop's own CAA
	add("C=US, O=DigiCert Inc, CN=DigiCert TLS", old, "www.acme.test")                                  // older than 30 days: not checked
	add("C=XX, O=Unknown Regional CA, CN=Unknown", recent, "www.acme.test")                             // issuer not recognised: never reported
	tg := h.addTarget("acme.test", "")
	h.scan(tg.ID)
	fs := findingsOf(t, h, "acme.test", "ct-unauthorized-ca", "")
	var got []string
	for _, f := range fs {
		got = append(got, f.Host+" "+issuerOrg(strings.SplitN(strings.SplitN(f.Detail, " by ", 2)[1], ", which", 2)[0]))
		if f.Severity != "high" || !strings.Contains(f.Detail, "crt.sh id") {
			t.Errorf("finding: %+v", f)
		}
	}
	if len(fs) != 2 || !strings.Contains(strings.Join(got, "|"), "www.acme.test DigiCert Inc") || !strings.Contains(strings.Join(got, "|"), "acme.test Let's Encrypt") {
		t.Fatalf("want DigiCert on www and Let's Encrypt on the wildcard, got %q", got)
	}
	// stays open on the next scan: an issued certificate is closed by hand
	h.scan(tg.ID)
	if n := findingsOf(t, h, "acme.test", "ct-unauthorized-ca", "open"); len(n) != 2 {
		t.Errorf("findings closed by themselves: %d open", len(n))
	}
}

func TestShadowITFromCT(t *testing.T) {
	h := newHarness(t)
	h.dns.add(t, "acme.test. 60 IN A 203.0.113.10")
	h.dns.add(t, "www.acme.test. 60 IN A 203.0.113.10")
	h.src.addCert("acme.test", "www.acme.test")
	tg := h.addTarget("acme.test", "")
	h.scan(tg.ID) // baseline: nothing is new yet
	if f := openFindingOf(t, h, "acme.test", "shadow-it-ct-subdomain", "www.acme.test"); f != nil {
		t.Fatalf("baseline host reported: %+v", f)
	}
	h.dns.add(t, "newapp.acme.test. 60 IN A 203.0.113.77")
	h.src.addCert("newapp.acme.test", "planned.acme.test") // planned does not resolve yet
	h.scan(tg.ID)
	f := openFindingOf(t, h, "acme.test", "shadow-it-ct-subdomain", "newapp.acme.test")
	if f == nil || f.Severity != "low" || !strings.Contains(f.Detail, "203.0.113.77") {
		t.Fatalf("new live CT host not reported: %+v", f)
	}
	if f := openFindingOf(t, h, "acme.test", "shadow-it-ct-subdomain", "planned.acme.test"); f != nil {
		t.Errorf("CT name that does not resolve reported: %+v", f)
	}
	h.scan(tg.ID) // still open next time: it waits for a review
	if f := openFindingOf(t, h, "acme.test", "shadow-it-ct-subdomain", "newapp.acme.test"); f == nil {
		t.Error("finding closed by itself")
	}
	h.dns.remove("newapp.acme.test.", 1) // the host is taken down
	h.scan(tg.ID)
	if f := openFindingOf(t, h, "acme.test", "shadow-it-ct-subdomain", "newapp.acme.test"); f != nil {
		t.Errorf("finding open after the host went away: %+v", f)
	}
}
