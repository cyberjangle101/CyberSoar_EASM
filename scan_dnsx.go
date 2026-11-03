package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS hygiene beyond single records: delegated zones whose nameservers no longer serve them
// or whose nameserver domain has lapsed (EASM-DNS-008), mail servers on lapsed or missing
// names (EASM-DNS-009), certificates from an authority the CAA record does not allow
// (EASM-TLS-012), and newly published hosts first seen in Certificate Transparency
// (EASM-TLS-013). Everything here is ordinary DNS: resolver lookups, plus one
// non-recursive question to a nameserver, as any resolver asks.

// dnsxFinding is a finding computed before the scan's transaction and raised inside it.
type dnsxFinding struct{ key, kind, sev, host, detail, source string }

type dnsxData struct {
	findings []dnsxFinding
	checked  map[string]bool            // finding keys evaluated reliably this scan; only these may be resolved
	mx       map[string]map[string]bool // host -> its current mail servers, for hosts whose MX lookup worked
}

func (d *dnsxData) reliable(key string) bool {
	if d == nil {
		return false
	}
	if d.checked[key] {
		return true
	}
	// A mail server that is no longer in the host's MX records has nothing left to report.
	if rest, ok := strings.CutPrefix(key, "dangling-mx:"); ok {
		if host, target, ok := strings.Cut(rest, ":"); ok {
			if cur, looked := d.mx[host]; looked && !cur[target] {
				return true
			}
		}
	}
	return false
}

func (d *dnsxData) add(f dnsxFinding) {
	d.findings = append(d.findings, f)
	d.checked[f.key] = true
}

// maxDelegationChecks caps how many delegated zones one scan examines.
const maxDelegationChecks = 50

// regState is what DNS and RDAP say about a registrable domain.
type regState int

const (
	regUnknown      regState = iota // the lookups failed
	regRegistered                   // it exists in DNS
	regUnregistered                 // the registry has no such domain (NXDOMAIN, and RDAP agrees or was not asked)
	regHeld                         // registered (RDAP) but withdrawn from DNS: on hold or expired
)

func (s *Scanner) registration(ctx context.Context, dom string, cache map[string]regState) regState {
	if st, ok := cache[dom]; ok {
		return st
	}
	st := regUnknown
	if exists, ok := s.res.Exists(ctx, dom); ok {
		st = regRegistered
		if !exists {
			st = regUnregistered
			if s.cfg.Intel.RDAP {
				if _, err := s.enr.RDAPDomain(ctx, dom); err == nil {
					st = regHeld
				}
			}
		}
	}
	cache[dom] = st
	return st
}

func (st regState) describe(name, dom string) string {
	switch st {
	case regUnregistered:
		return fmt.Sprintf("%s is on %s, which is not registered: anyone can register it and then answer for this name", name, dom)
	case regHeld:
		return fmt.Sprintf("%s is on %s, which is registered but no longer published in DNS (expired or on hold): if it lapses, anyone can register it", name, dom)
	}
	return ""
}

// cloudDNSProviders are DNS hosts where anyone can create a zone for any name, so a
// delegation to them that is no longer served can be claimed.
var cloudDNSProviders = []struct{ suffix, name string }{
	{".awsdns-", "Amazon Route 53"}, {".azure-dns.", "Azure DNS"}, {".digitalocean.com", "DigitalOcean"},
	{".googledomains.com", "Google Cloud DNS"}, {"ns-cloud-", "Google Cloud DNS"}, {".linode.com", "Linode"},
	{".dnsmadeeasy.com", "DNS Made Easy"}, {".dnsimple.com", "DNSimple"}, {".ns1.com", "NS1"}, {".nsone.net", "NS1"},
	{".vultr.com", "Vultr"}, {".hetzner.com", "Hetzner"}, {".domaincontrol.com", "GoDaddy"}, {".cloudflare.com", "Cloudflare"},
}

func cloudDNSProvider(ns string) string {
	for _, p := range cloudDNSProviders {
		if strings.Contains(ns, p.suffix) {
			return p.name
		}
	}
	return ""
}

// checkDelegations runs EASM-DNS-008 and EASM-DNS-009.
func (s *Scanner) checkDelegations(ctx context.Context, root string, hosts []string, results map[string]*HostResult) *dnsxData {
	d := &dnsxData{checked: map[string]bool{}, mx: map[string]map[string]bool{}}
	own := registrable(root)
	reg := map[string]regState{}

	// The domain's own nameservers, used to read delegations straight from the parent zone:
	// when a delegated zone is broken, resolvers only answer SERVFAIL and hide its NS records.
	var parentIPs []string
	if rr := results[root]; rr != nil {
		for _, ns := range rr.Records["NS"] {
			if ips, _, err := s.res.Addrs(ctx, ns); err == nil {
				for _, ip := range ips {
					if publicIP(ip) || s.res.authAddr != nil {
						parentIPs = append(parentIPs, ip)
					}
				}
			}
			if len(parentIPs) >= 2 {
				break
			}
		}
	}

	checked := 0
	for _, h := range hosts {
		if ctx.Err() != nil {
			return d
		}
		hr := results[h]
		if hr == nil || hr.NX {
			continue
		}
		nsNames := hr.Records["NS"]
		failed := hr.Failed["NS"] || hr.Failed["A"] || hr.Failed["SOA"]
		if h != root && len(nsNames) == 0 && failed && len(parentIPs) > 0 && checked < maxDelegationChecks {
			nsNames = s.delegationFromParent(ctx, parentIPs, h)
		}
		if len(nsNames) > 0 && checked < maxDelegationChecks {
			checked++
			s.checkZone(ctx, d, root, own, h, nsNames, reg)
		} else if len(nsNames) == 0 && !failed {
			d.checked["dangling-ns:"+h] = true // not a delegated zone, nothing to report
		}
		s.checkMailServers(ctx, d, own, h, hr, reg)
	}
	return d
}

// delegationFromParent asks the domain's own nameservers which nameservers a child zone is delegated to.
func (s *Scanner) delegationFromParent(ctx context.Context, parentIPs []string, zone string) []string {
	for _, ip := range parentIPs {
		in, err := s.res.AskServer(ctx, ip, zone, dns.TypeNS)
		if err != nil || in.Rcode != dns.RcodeSuccess {
			continue
		}
		var out []string
		for _, rr := range append(append([]dns.RR{}, in.Answer...), in.Ns...) {
			if ns, ok := rr.(*dns.NS); ok && cleanName(ns.Hdr.Name) == zone {
				out = append(out, cleanName(ns.Ns))
			}
		}
		return dedupe(out)
	}
	return nil
}

// checkZone looks at one delegated zone's nameservers: are their domains registered, and do they serve the zone?
func (s *Scanner) checkZone(ctx context.Context, d *dnsxData, root, own, zone string, nsNames []string, reg map[string]regState) {
	key := "dangling-ns:" + zone
	sort.Strings(nsNames)
	var lapsed []string
	worst := regRegistered
	sure := true
	for _, ns := range nsNames {
		dom := registrable(ns)
		if dom == "" || dom == own {
			continue // the domain being scanned is registered
		}
		switch st := s.registration(ctx, dom, reg); st {
		case regUnknown:
			sure = false
		case regUnregistered, regHeld:
			lapsed = append(lapsed, st.describe("nameserver "+ns, dom))
			if worst != regUnregistered {
				worst = st
			}
		}
	}
	if len(lapsed) > 0 {
		sev := "high"
		if worst == regHeld {
			sev = "medium"
		}
		d.add(dnsxFinding{key, "dangling-ns", sev, zone, fmt.Sprintf("%s is delegated to nameservers whose domain has lapsed: %s. Whoever registers it controls every record under %s",
			zone, strings.Join(lapsed, "; "), zone), "DNS + RDAP"})
		return
	}
	if zone == root {
		if sure {
			d.checked[key] = true
		}
		return // the domain's own nameservers: if they did not serve it, nothing else here would resolve
	}

	// Lame delegation: none of the delegated nameservers will answer for the zone.
	lame, answered := 0, 0
	var why []string
	for _, ns := range nsNames {
		ips, nx, err := s.res.Addrs(ctx, ns)
		switch {
		case err != nil:
			continue
		case nx || len(ips) == 0:
			answered++
			lame++
			why = append(why, ns+" does not exist")
			continue
		}
		ip := ips[0]
		if !publicIP(ip) && s.res.authAddr == nil {
			continue
		}
		in, err := s.res.AskServer(ctx, ip, zone, dns.TypeSOA)
		if err != nil {
			continue
		}
		answered++
		switch {
		case in.Rcode == dns.RcodeRefused || in.Rcode == dns.RcodeServerFailure:
			lame++
			why = append(why, fmt.Sprintf("%s (%s) answers %s", ns, ip, dns.RcodeToString[in.Rcode]))
		case !in.Authoritative:
			lame++
			why = append(why, fmt.Sprintf("%s (%s) does not hold the zone", ns, ip))
		}
	}
	if answered < len(nsNames) || !sure {
		return // some nameservers could not be checked: no conclusion either way
	}
	d.checked[key] = true
	if lame == 0 || lame < len(nsNames) {
		return
	}
	detail := fmt.Sprintf("%s is delegated to nameservers that do not serve it: %s. Resolvers get no answer for anything under %s", zone, strings.Join(why, "; "), zone)
	if p := cloudDNSProvider(nsNames[0]); p != "" {
		detail += fmt.Sprintf(". The nameservers belong to %s, where anyone can create a zone for this name and take it over", p)
	} else {
		detail += ". If the nameserver's operator lets customers create zones for any name, whoever creates this one takes it over"
	}
	d.add(dnsxFinding{key, "dangling-ns", "high", zone, detail, "DNS"})
}

// checkMailServers looks at the mail servers a name publishes (EASM-DNS-009).
func (s *Scanner) checkMailServers(ctx context.Context, d *dnsxData, own, h string, hr *HostResult, reg map[string]regState) {
	if !hr.Failed["MX"] {
		d.mx[h] = map[string]bool{}
		for _, mx := range hr.Records["MX"] {
			if f := strings.Fields(mx); len(f) == 2 {
				d.mx[h][f[1]] = true
			}
		}
	}
	for _, mx := range hr.Records["MX"] {
		f := strings.Fields(mx)
		if len(f) != 2 || f[1] == "." {
			continue
		}
		target := f[1]
		key := "dangling-mx:" + h + ":" + target
		dom := registrable(target)
		if dom != "" && dom != own {
			switch st := s.registration(ctx, dom, reg); st {
			case regUnknown:
				continue
			case regUnregistered, regHeld:
				sev := "high"
				if st == regHeld {
					sev = "medium"
				}
				d.add(dnsxFinding{key, "dangling-mx", sev, h, fmt.Sprintf("Mail for %s goes to %s. %s, and receive the mail sent to %s",
					h, target, st.describe("The mail server "+target, dom), h), "DNS + RDAP"})
				continue
			}
		}
		ips, nx, err := s.res.Addrs(ctx, target)
		if err != nil {
			continue
		}
		d.checked[key] = true
		if nx {
			d.add(dnsxFinding{key, "dangling-mx", "low", h, fmt.Sprintf("Mail for %s goes to %s, which does not exist in DNS, so mail to %s cannot be delivered there. "+
				"It is usually a mail service that was given up but whose record was left behind", h, target, h), "DNS"})
		}
		_ = ips
	}
}

// ---- EASM-TLS-012: certificates from an authority the CAA record does not allow

// caaFamilies maps certificate authorities, as named in a certificate's issuer, to the CAA
// identifiers that allow them. A certificate is checked only when its issuer is recognised,
// so an authority missing from this list never causes a finding.
var caaFamilies = []struct{ orgs, caa []string }{
	{[]string{"let's encrypt", "isrg"}, []string{"letsencrypt.org"}},
	{[]string{"zerossl"}, []string{"sectigo.com", "zerossl.com"}},
	{[]string{"sectigo", "comodo", "usertrust"}, []string{"sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"}},
	{[]string{"digicert", "thawte", "geotrust", "rapidssl", "symantec", "encryption everywhere"}, []string{"digicert.com", "symantec.com", "thawte.com", "geotrust.com", "rapidssl.com", "digitalcertvalidation.com"}},
	{[]string{"globalsign"}, []string{"globalsign.com"}},
	{[]string{"amazon"}, []string{"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"}},
	{[]string{"google trust services"}, []string{"pki.goog", "google.com"}},
	{[]string{"godaddy", "starfield"}, []string{"godaddy.com", "starfieldtech.com"}},
	{[]string{"entrust", "affirmtrust"}, []string{"entrust.net", "affirmtrust.com"}},
	{[]string{"ssl corporation", "ssl.com"}, []string{"ssl.com"}},
	{[]string{"buypass"}, []string{"buypass.com", "buypass.no"}},
	{[]string{"certum", "asseco", "unizeto"}, []string{"certum.pl", "certum.eu"}},
	{[]string{"identrust"}, []string{"identrust.com"}},
	{[]string{"harica", "hellenic academic"}, []string{"harica.gr"}},
	{[]string{"microsoft"}, []string{"microsoft.com", "digicert.com"}},
	{[]string{"apple"}, []string{"apple.com"}},
}

// issuerOrg returns the O= part of an issuer name, or the whole name.
func issuerOrg(issuer string) string {
	for _, p := range strings.Split(issuer, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "O") {
			return strings.TrimSpace(v)
		}
	}
	return issuer
}

// caaFor returns the CAA identifiers that allow a certificate's issuer, or nil when the issuer is not recognised.
func caaFor(issuer string) []string {
	org := strings.ToLower(issuerOrg(issuer))
	for _, f := range caaFamilies {
		for _, o := range f.orgs {
			if strings.Contains(org, o) {
				return f.caa
			}
		}
	}
	return nil
}

// caaSet is what one name's CAA records allow.
type caaSet struct {
	issue, wild []string
	hasWild     bool
}

func (c caaSet) allows(ids []string, wildcard bool) bool {
	list := c.issue
	if wildcard && c.hasWild {
		list = c.wild
	}
	for _, a := range list {
		for _, id := range ids {
			if a == id {
				return true
			}
		}
	}
	return false
}

// readCAA reads one name's CAA records; found is false when it has none, ok false when the lookup failed.
func (s *Scanner) readCAA(ctx context.Context, name string) (set caaSet, found, ok bool) {
	in, err := s.res.query(ctx, name, dns.TypeCAA)
	if err != nil {
		return set, false, false
	}
	if in.Rcode != dns.RcodeSuccess {
		return set, false, true
	}
	for _, rr := range in.Answer {
		c, isCAA := rr.(*dns.CAA)
		if !isCAA {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(strings.SplitN(c.Value, ";", 2)[0]))
		switch strings.ToLower(c.Tag) {
		case "issue":
			found = true
			set.issue = append(set.issue, v)
		case "issuewild":
			found = true
			set.hasWild = true
			set.wild = append(set.wild, v)
		}
	}
	return set, found, true
}

// effectiveCAA finds the CAA records that govern a name: its own, or the closest parent's (RFC 8659).
func (s *Scanner) effectiveCAA(ctx context.Context, name, root string, cache map[string]*caaSet) (*caaSet, bool) {
	for n := strings.TrimPrefix(name, "*."); ; {
		if c, seen := cache[n]; seen {
			return c, true
		}
		set, found, ok := s.readCAA(ctx, n)
		if !ok {
			return nil, false
		}
		if found {
			cache[n] = &set
			return &set, true
		}
		if n == root || !strings.Contains(n, ".") {
			cache[n] = nil
			return nil, true
		}
		n = n[strings.Index(n, ".")+1:]
	}
}

// ctCertWindow is how recent a certificate must be for the CAA comparison: older ones may predate the CAA record.
const ctCertWindow = 30 * 24 * time.Hour

func parseCTTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// checkCertAuthorities runs EASM-TLS-012 over the certificates Certificate Transparency lists.
func (s *Scanner) checkCertAuthorities(ctx context.Context, root string, certs map[string]CertInfo, now time.Time) []dnsxFinding {
	var out []dnsxFinding
	cache := map[string]*caaSet{}
	keys := sortedKeys(certs)
	for _, k := range keys {
		c := certs[k]
		nb, ok1 := parseCTTime(c.NotBefore)
		na, ok2 := parseCTTime(c.NotAfter)
		if !ok1 || !ok2 || now.Sub(nb) > ctCertWindow || now.After(na) {
			continue
		}
		ids := caaFor(c.Issuer)
		if ids == nil {
			continue
		}
		var refused []string
		for _, n := range c.Names {
			name := strings.ToLower(strings.TrimSuffix(n, "."))
			set, ok := s.effectiveCAA(ctx, name, root, cache)
			if !ok || set == nil {
				continue // lookup failed, or no CAA anywhere up the tree: nothing restricts issuance
			}
			if !set.allows(ids, strings.HasPrefix(name, "*.")) {
				refused = append(refused, name)
			}
		}
		if len(refused) == 0 {
			continue
		}
		host := c.CommonName
		if host == "" {
			host = refused[0]
		}
		out = append(out, dnsxFinding{"ctca:" + c.Key, "ct-unauthorized-ca", "high", strings.TrimPrefix(host, "*."),
			fmt.Sprintf("A certificate for %s was issued on %s by %s, which the domain's CAA record does not allow (it allows: %s). "+
				"Either an authority ignored CAA, the record changed, or the certificate was obtained some other way. crt.sh id %d",
				strings.Join(refused, ", "), nb.Format("2006-01-02"), issuerOrg(c.Issuer), s.allowedCAA(cache, refused[0]), c.CrtShID), "Certificate Transparency + CAA"})
	}
	return out
}

func (s *Scanner) allowedCAA(cache map[string]*caaSet, name string) string {
	for n := strings.TrimPrefix(name, "*."); ; n = n[strings.Index(n, ".")+1:] {
		if c := cache[n]; c != nil {
			list := c.issue
			if strings.HasPrefix(name, "*.") && c.hasWild {
				list = c.wild
			}
			if len(list) == 1 && list[0] == "" {
				return "no authority at all"
			}
			return strings.Join(list, ", ")
		}
		if !strings.Contains(n, ".") {
			return "unknown"
		}
	}
}

// liveAddrs lists a host's addresses that are not wildcard answers ("" when it has none).
func liveAddrs(hr *HostResult, wildcard map[string]struct{}) string {
	var out []string
	for _, rt := range []string{"A", "AAAA"} {
		for _, ip := range hr.Records[rt] {
			if _, w := wildcard[ip]; !w {
				out = append(out, ip)
			}
		}
	}
	return strings.Join(out, ", ")
}

// ---- EASM-DNS-012: registry transfer lock

// transferLocked says whether RDAP shows a transfer prohibition set by the registrar or the registry.
func transferLocked(status []string) bool {
	for _, st := range status {
		v := strings.ReplaceAll(strings.ToLower(st), " ", "")
		if v == "clienttransferprohibited" || v == "servertransferprohibited" {
			return true
		}
	}
	return false
}

// lockApplies is false for country-code domains, many of whose registries do not use transfer statuses.
func lockApplies(domain string) bool {
	i := strings.LastIndex(domain, ".")
	return i > 0 && len(domain)-i-1 > 2
}
