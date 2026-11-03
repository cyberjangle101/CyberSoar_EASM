package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Threat-intelligence additions (all off by default): certificates issued for look-alike
// domains (EASM-BRAND-005), look-alike sites that copy yours (EASM-BRAND-004), internal package
// names anyone could publish (EASM-BRAND-006), and your addresses on spam blocklists
// (EASM-MAIL-018).

// ---- EASM-BRAND-005: certificates on look-alikes

// maxLookalikeCertChecks caps the Certificate Transparency lookups per scan.
const maxLookalikeCertChecks = 10

type lookCert struct {
	Domain, Issuer, Names string
	NotBefore             time.Time
	CrtShID               int64
}

// lookalikeCerts finds certificates issued in the last 30 days for the reported look-alikes.
func (s *Scanner) lookalikeCerts(ctx context.Context, d *extraData) {
	d.lookCertsRan = map[string]bool{}
	now := time.Now().UTC()
	for i, h := range d.lookHits {
		if i >= maxLookalikeCertChecks || ctx.Err() != nil {
			break
		}
		_, certs, err := s.disc.fetchCrtSh(ctx, h.Domain)
		if err != nil {
			continue
		}
		d.lookCertsRan[h.Domain] = true
		for _, c := range certs {
			nb, ok1 := parseCTTime(c.NotBefore)
			na, ok2 := parseCTTime(c.NotAfter)
			if !ok1 || !ok2 || now.Sub(nb) > ctCertWindow || now.After(na) {
				continue
			}
			d.lookCerts = append(d.lookCerts, lookCert{Domain: h.Domain, Issuer: issuerOrg(c.Issuer), Names: strings.Join(c.Names, ", "), NotBefore: nb, CrtShID: c.CrtShID})
			break // the newest is enough to make the point
		}
	}
}

// ---- EASM-BRAND-004: look-alike sites that copy yours

// mmh3 is MurmurHash3 (x86, 32-bit), the hash Shodan uses for favicons.
func mmh3(data []byte) int32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// faviconHash is Shodan's favicon hash: MurmurHash3 of the base64 text with a newline every 76 characters.
func faviconHash(icon []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(icon)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\n")
	return mmh3([]byte(b.String()))
}

// siteLook is what a home page and its icon look like.
type siteLook struct {
	Title    string
	Icon     int32
	HasIcon  bool
	Password bool // the page has a password field
	Body     string
}

var passwordFieldRe = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)

// lookAt fetches a site's home page and /favicon.ico (HTTPS, then HTTP).
func (s *Scanner) lookAt(ctx context.Context, pr *Prober, host string) (*siteLook, bool) {
	ips, _, err := s.res.Addrs(ctx, host)
	if err != nil || len(ips) == 0 || !pr.allow(net.ParseIP(ips[0])) {
		return nil, false
	}
	ip := ips[0]
	for _, sc := range []struct {
		scheme string
		port   int
	}{{"https", 443}, {"http", 80}} {
		home, err := pr.fetch(ctx, sc.scheme, host, ip, sc.port, "/")
		if err != nil {
			continue
		}
		l := &siteLook{Title: pageTitle(home.Body), Password: passwordFieldRe.Match(home.Body), Body: strings.ToLower(string(home.Body))}
		if ic, err := pr.fetch(ctx, sc.scheme, host, ip, sc.port, "/favicon.ico"); err == nil && ic.Status == 200 && len(ic.Body) > 0 && notHTML(ic.Header) {
			l.Icon, l.HasIcon = faviconHash(ic.Body), true
		}
		return l, true
	}
	return nil, false
}

// cloneCheck compares each look-alike that has a web site with the organisation's own home page.
func (s *Scanner) cloneCheck(ctx context.Context, root string, d *extraData) {
	pr := s.prober
	if pr == nil {
		pr = NewProber(s.cfg.Active)
	}
	var own *siteLook
	for _, h := range []string{root, "www." + root} {
		if l, ok := s.lookAt(ctx, pr, h); ok {
			own = l
			break
		}
	}
	if own == nil {
		return // nothing to compare with
	}
	brand := strings.ToLower(strings.SplitN(root, ".", 2)[0])
	d.cloneChecked = map[string]bool{}
	for _, h := range d.lookHits {
		if !h.Web || ctx.Err() != nil {
			continue
		}
		l, ok := s.lookAt(ctx, pr, h.Domain)
		if !ok {
			continue
		}
		d.cloneChecked[h.Domain] = true
		var why []string
		sev := ""
		if own.HasIcon && l.HasIcon && own.Icon == l.Icon {
			why = append(why, fmt.Sprintf("it serves your exact site icon (favicon hash %d, searchable in Shodan as http.favicon.hash:%d)", l.Icon, l.Icon))
			sev = "high"
		}
		if l.Password && (own.Title != "" && l.Title == own.Title || len(brand) >= 4 && strings.Contains(l.Body, brand)) {
			why = append(why, "it shows a password field on a page that uses your name or title")
			sev = "high"
		}
		if sev == "" && own.Title != "" && l.Title == own.Title {
			why = append(why, fmt.Sprintf("its home page has your page title %q", own.Title))
			sev = "medium"
		}
		if sev != "" {
			d.clones = append(d.clones, dnsxFinding{key: "clone:" + root + ":" + h.Domain, kind: "phishing-clone", sev: sev, host: h.Domain,
				detail: fmt.Sprintf("%s looks like a copy of your site: %s. This is a likely phishing site; it was checked with an ordinary visit to its home page and icon.", h.Domain, strings.Join(why, "; and ")),
				source: "Look-alike site visit"})
		}
	}
}

// ---- EASM-BRAND-006: internal package names anyone could publish

var (
	sourceMapRe = regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s'"]+)`)
	nodeModRe   = regexp.MustCompile(`node_modules/((?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)`)
	reqLineRe   = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[=<>!~]=|>|<|$|\[|;)`)
)

// pkgRef is a package name a site reveals, and where.
type pkgRef struct {
	Registry, Name, Where string
}

// sitePackages collects the package names one web service reveals: npm names from the source
// maps of its own scripts and from /package.json, PyPI names from /requirements.txt.
func (p *Prober) sitePackages(ctx context.Context, wr *WebResult) []pkgRef {
	var out []pkgRef
	seen := map[string]bool{}
	addRef := func(reg, name, where string) {
		if k := reg + "/" + name; !seen[k] && len(out) < 200 {
			seen[k] = true
			out = append(out, pkgRef{reg, name, where})
		}
	}
	home, err := p.fetch(ctx, wr.Scheme, wr.Host, wr.IP, wr.Port, "/")
	if err == nil && home.Status == 200 {
		n := 0
		for _, m := range scriptSrcRe.FindAllSubmatch(home.Body, 50) {
			src := string(m[1])
			u, err := url.Parse(src)
			if err != nil || (u.Host != "" && !strings.EqualFold(u.Hostname(), wr.Host)) || n >= 5 || ctx.Err() != nil {
				continue // only the site's own scripts
			}
			n++
			js, err := p.fetchLimit(ctx, wr.Scheme, wr.Host, wr.IP, wr.Port, u.Path, 4<<20)
			if err != nil || js.Status != 200 {
				continue
			}
			sm := sourceMapRe.FindSubmatch(js.Body)
			if sm == nil || strings.HasPrefix(string(sm[1]), "data:") {
				continue
			}
			mapURL, err := u.Parse(string(sm[1]))
			if err != nil || (mapURL.Host != "" && !strings.EqualFold(mapURL.Hostname(), wr.Host)) {
				continue
			}
			mp, err := p.fetchLimit(ctx, wr.Scheme, wr.Host, wr.IP, wr.Port, mapURL.Path, 16<<20)
			if err != nil || mp.Status != 200 {
				continue
			}
			var smap struct {
				Sources []string `json:"sources"`
			}
			if json.Unmarshal(mp.Body, &smap) != nil {
				continue
			}
			for _, src := range smap.Sources {
				for _, mm := range nodeModRe.FindAllStringSubmatch(src, -1) {
					addRef("npm", mm[1], wr.URL()+strings.TrimPrefix(mapURL.Path, "/"))
				}
			}
		}
	}
	if pj, err := p.fetch(ctx, wr.Scheme, wr.Host, wr.IP, wr.Port, "/package.json"); err == nil && pj.Status == 200 && notHTML(pj.Header) {
		var pkg struct {
			Dependencies, DevDependencies map[string]string
		}
		if json.Unmarshal(pj.Body, &pkg) == nil {
			for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
				for _, name := range sortedKeys(deps) {
					if v := deps[name]; !strings.Contains(v, ":") && !strings.Contains(v, "/") { // skip git:, file: and URL dependencies
						addRef("npm", name, wr.URL()+"package.json")
					}
				}
			}
		}
	}
	if rq, err := p.fetch(ctx, wr.Scheme, wr.Host, wr.IP, wr.Port, "/requirements.txt"); err == nil && rq.Status == 200 && notHTML(rq.Header) {
		for _, m := range reqLineRe.FindAllStringSubmatch(string(rq.Body), 200) {
			if !strings.HasPrefix(m[1], "-") {
				addRef("pypi", strings.ToLower(m[1]), wr.URL()+"requirements.txt")
			}
		}
	}
	return out
}

// PackageExists asks npm or PyPI whether a package name is taken. ok is false when the registry did not answer.
func (e *Enricher) PackageExists(ctx context.Context, registry, name string) (exists, ok bool) {
	var u string
	switch registry {
	case "npm":
		u = e.urls.npm + url.PathEscape(name)
	case "pypi":
		u = e.urls.pypi + url.PathEscape(name) + "/json"
	default:
		return false, false
	}
	err := e.getJSON(ctx, u, nil, nil)
	switch {
	case err == nil:
		return true, true
	case errors.Is(err, errNoData):
		return false, true
	}
	return false, false
}

// dependencyConfusion checks the package names the organisation's web services reveal.
func (s *Scanner) dependencyConfusion(ctx context.Context, d *activeData, pr *Prober) {
	cache := map[string]bool{}
	sites := 0
	for _, wr := range d.results {
		if sites >= 10 || ctx.Err() != nil {
			break
		}
		if wr.Status != 200 {
			continue
		}
		sites++
		refs := pr.sitePackages(ctx, wr)
		sort.Slice(refs, func(i, j int) bool { return refs[i].Registry+refs[i].Name < refs[j].Registry+refs[j].Name })
		for _, r := range refs {
			k := r.Registry + "/" + r.Name
			exists, done := cache[k]
			if !done {
				var known bool
				exists, known = s.enr.PackageExists(ctx, r.Registry, r.Name)
				if !known {
					delete(d.scopes, webScope(wr.Host, wr.Port)) // a registry did not answer: no conclusion for this site
					continue
				}
				cache[k] = exists
			}
			if exists {
				continue
			}
			sev := "high"
			why := "anyone can publish a package with that name, and a build that also looks in the public registry would install it"
			if strings.HasPrefix(r.Name, "@") {
				sev = "medium"
				why = "if the scope " + strings.SplitN(r.Name, "/", 2)[0] + " is not registered to you on npm, anyone can claim it and publish this package"
			}
			reg := map[string]string{"npm": "npm (https://www.npmjs.com/package/" + r.Name + ")", "pypi": "PyPI (https://pypi.org/project/" + r.Name + "/)"}[r.Registry]
			d.extra = append(d.extra, dnsxFinding{key: fmt.Sprintf("web:dependency-confusion:%s:%d:%s", wr.Host, wr.Port, r.Registry+"-"+strings.ReplaceAll(r.Name, ":", "")),
				kind: "dependency-confusion", sev: sev, host: wr.Host,
				detail: fmt.Sprintf("%s reveals the package %q (in %s), which does not exist on %s: %s.", wr.URL(), r.Name, r.Where, reg, why)})
		}
	}
}

// ---- EASM-MAIL-018: spam blocklists

// dnsblZones are free blocklists that answer through public resolvers.
var dnsblZones = []struct{ zone, name string }{
	{"bl.spamcop.net", "SpamCop"},
	{"psbl.surriel.com", "PSBL"},
}

// dnsblCheck looks the domain's mail addresses (MX servers and single SPF ip4: entries) and web
// addresses (the domain and www) up on the blocklists, and raises one finding for the domain.
func (s *Scanner) dnsblCheck(ctx context.Context, root string, results map[string]*HostResult, m *mailPosture) {
	role := map[string]string{} // address -> "mail" or "web"
	if hr := results[root]; hr != nil {
		for _, mx := range hr.Records["MX"] {
			f := strings.Fields(mx)
			if len(f) != 2 || f[1] == "." {
				continue
			}
			if ips, _, err := s.res.Addrs(ctx, f[1]); err == nil {
				for _, ip := range ips {
					role[ip] = "mail"
				}
			}
		}
		for _, rec := range spfRecords(hr.Records["TXT"]) {
			for _, tok := range strings.Fields(rec) {
				v := strings.TrimPrefix(strings.TrimPrefix(tok, "+"), "ip4:")
				if v != tok && net.ParseIP(strings.TrimSuffix(v, "/32")) != nil {
					role[strings.TrimSuffix(v, "/32")] = "mail"
				}
			}
		}
	}
	for _, h := range []string{root, "www." + root} {
		if hr := results[h]; hr != nil {
			for _, ip := range hr.Records["A"] {
				if _, seen := role[ip]; !seen {
					role[ip] = "web"
				}
			}
		}
	}
	ips := sortedKeys(role)
	if len(ips) > 50 {
		ips = ips[:50]
	}
	var listed []string
	mail, sure := false, true
	for _, ip := range ips {
		if !publicIP(ip) || net.ParseIP(ip).To4() == nil {
			continue
		}
		var on []string
		for _, z := range dnsblZones {
			yes, ok := s.dnsblListed(ctx, ip, z.zone)
			if !ok {
				sure = false
				continue
			}
			if yes {
				on = append(on, z.name)
			}
		}
		if len(on) > 0 {
			listed = append(listed, fmt.Sprintf("%s (%s address) on %s", ip, role[ip], strings.Join(on, ", ")))
			mail = mail || role[ip] == "mail"
		}
	}
	if len(listed) > 0 {
		sev := "medium"
		if mail {
			sev = "high"
		}
		m.add(root, "dnsbl-listed", sev, fmt.Sprintf("Addresses of %s are on spam blocklists: %s. Mail from a listed address is rejected or sent to spam by many receivers; "+
			"a listing usually means the server sent spam, often because it or an account on it was compromised", root, strings.Join(listed, "; ")))
		return
	}
	if sure {
		m.did(root, "dnsbl-listed")
	}
}

// dnsblListed looks an IPv4 address up on one list: listed, or ok=false when the lookup failed or the list refused it.
func (s *Scanner) dnsblListed(ctx context.Context, ip, zone string) (listed, ok bool) {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return false, false
	}
	in, err := s.res.query(ctx, fmt.Sprintf("%d.%d.%d.%d.%s", p[3], p[2], p[1], p[0], zone), 1) // A
	if err != nil {
		return false, false
	}
	if in.Rcode != 0 {
		return false, true // NXDOMAIN: not listed
	}
	answers := collectRRs(in, cleanName(fmt.Sprintf("%d.%d.%d.%d.%s", p[3], p[2], p[1], p[0], zone)), 1)
	switch {
	case len(answers) == 0:
		return false, true
	case strings.HasPrefix(answers[0], "127.0.0."):
		return true, true
	}
	return false, false // any other answer is an error code from the list operator (for example a refused lookup)
}
