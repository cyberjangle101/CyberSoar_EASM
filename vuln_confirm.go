package main

import (
	"regexp"
	"sort"
	"strings"
)

// ---- EASM-EXP-002: corroborating CVE findings with the agent's own observation
//
// Exposure data (Shodan InternetDB) lists CVEs it infers from the product and version it saw
// on an address (its CPEs). That inference goes stale when the software is upgraded, so on its
// own it is one unconfirmed source. When the agent's active web check sees the same product at
// the same version in the server's own headers, the version is confirmed first-hand.

// banners lists, per address, the Server and X-Powered-By headers the active checks saw.
func (a *activeData) banners() map[string][]string {
	out := map[string][]string{}
	if a == nil {
		return out
	}
	for _, wr := range a.results {
		for _, h := range []string{wr.Server, wr.Powered} {
			if h = strings.TrimSpace(h); h != "" && !containsStr(out[wr.IP], h) {
				out[wr.IP] = append(out[wr.IP], h)
			}
		}
	}
	return out
}

// rawCPEs collects the CPEs every exposure source reported for one address.
func rawCPEs(bySrc map[string]*IPIntel) []string {
	var out []string
	for _, src := range sortedKeys(bySrc) {
		out = append(out, bySrc[src].CPEs...)
	}
	return dedupe(out)
}

var versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9A-Za-z]+)+$`)

// versionSeen returns the header that shows one of the CPEs' products at its exact version
// ("Apache/2.4.49 (Unix)" for cpe:/a:apache:http_server:2.4.49), or "" when none does. A CPE
// without a dotted version is never matched: a bare "2" would match almost any header.
func versionSeen(cpes, banners []string) string {
	sort.Strings(banners)
	for _, c := range cpes {
		c = strings.TrimPrefix(strings.TrimPrefix(c, "cpe:2.3:"), "cpe:/")
		f := strings.Split(strings.ToLower(c), ":")
		if len(f) < 4 || !versionRe.MatchString(f[3]) {
			continue
		}
		vendor, product, ver := f[1], f[2], f[3]
		names := []string{vendor, product, strings.ReplaceAll(product, "_", " "), strings.ReplaceAll(product, "_", "-")}
		for _, b := range banners {
			lb := strings.ToLower(b)
			if !hasVersionToken(lb, ver) {
				continue
			}
			for _, n := range names {
				if len(n) >= 3 && strings.Contains(lb, n) {
					return truncate(b, 60)
				}
			}
		}
	}
	return ""
}

// hasVersionToken reports whether ver appears in s as a whole version, so "2.4.4" does not
// match "2.4.49".
func hasVersionToken(s, ver string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], ver)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(ver)
		before := start == 0 || !isVersionChar(s[start-1])
		after := end == len(s) || !isVersionChar(s[end])
		if before && after {
			return true
		}
		i = start + 1
	}
}

func isVersionChar(c byte) bool {
	return c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
}
