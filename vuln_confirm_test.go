package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestVersionSeenMatchesExactProductVersions(t *testing.T) {
	cases := []struct {
		cpes    []string
		banners []string
		want    string
	}{
		{[]string{"cpe:/a:apache:http_server:2.4.49"}, []string{"Apache/2.4.49 (Unix)"}, "Apache/2.4.49 (Unix)"},
		{[]string{"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}, []string{"nginx/1.18.0 (Ubuntu)"}, "nginx/1.18.0 (Ubuntu)"},
		{[]string{"cpe:/a:microsoft:internet_information_services:10.0"}, []string{"Microsoft-IIS/10.0"}, "Microsoft-IIS/10.0"},
		{[]string{"cpe:/a:php:php:7.4.3"}, []string{"nginx", "PHP/7.4.3"}, "PHP/7.4.3"},
		{[]string{"cpe:/a:apache:http_server:2.4.49"}, []string{"Apache/2.4.58 (Unix)"}, ""}, // upgraded since: the CVEs no longer apply
		{[]string{"cpe:/a:apache:http_server:2.4.4"}, []string{"Apache/2.4.49"}, ""},         // a prefix is not the version
		{[]string{"cpe:/a:apache:http_server"}, []string{"Apache"}, ""},                     // no version: nothing to confirm
		{[]string{"cpe:/a:openbsd:openssh:8.2"}, []string{"nginx/8.2"}, ""},                  // same number, other product
		{nil, []string{"Apache/2.4.49"}, ""},
	}
	for _, c := range cases {
		if got := versionSeen(c.cpes, c.banners); got != c.want {
			t.Errorf("versionSeen(%v, %v) = %q, want %q", c.cpes, c.banners, got, c.want)
		}
	}
}

// A CVE finding from InternetDB alone is unconfirmed (not counted or alerted). When the agent's own
// active check sees the server announce the same product and version, it becomes trusted; once the
// server is upgraded, it goes back to unconfirmed.
func TestCVEFindingTrustedWhenAgentSeesTheSameVersion(t *testing.T) {
	l := newWebLab(t)
	h := l.h
	st, _ := h.store.LoadSettings()
	st.InternetDBEnabled = true
	h.saveSettings(st)
	l.setProber()
	ip := "203.0.113.10" // www.example.test and example.test
	h.intel.idb[ip] = strings.Replace(idbBody(ip, []int{443}, []string{"CVE-2021-41773", "CVE-2021-42013"}, nil),
		`"cpes":[]`, `"cpes":["cpe:/a:apache:http_server:2.4.49"]`, 1)
	server := "Apache/2.4.49 (Unix)"
	cert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "www.example.test", "example.test")
	l.serve(ip, 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", server)
		_, _ = fmt.Fprint(w, "<html><title>Home</title></html>")
	}), &cert, tls.VersionTLS12)

	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	f := l.findingFor("known-vuln", "CVE-2021-41773")
	if f == nil {
		t.Fatalf("no CVE finding; open: %v", l.openKinds())
	}
	if f.Trust != trustTrusted || !strings.Contains(f.TrustSources, "Active check") || !strings.Contains(f.Detail, "same version (Apache/2.4.49 (Unix))") {
		t.Errorf("seen first-hand, the CVE finding should be trusted: trust %q, sources %q, detail %q", f.Trust, f.TrustSources, f.Detail)
	}
	if s, _ := h.store.Stats(); s.OpenFindings == 0 {
		t.Error("a trusted CVE finding should count in the open findings")
	}

	server = "Apache/2.4.58 (Unix)" // upgraded: exposure data is now out of date
	h.scanN(tg.ID, 1)
	if f = l.findingFor("known-vuln", "CVE-2021-41773"); f == nil || f.Trust != trustUnconfirmed {
		t.Errorf("after an upgrade the stale CVE data should be unconfirmed again: %+v", f)
	}
}
