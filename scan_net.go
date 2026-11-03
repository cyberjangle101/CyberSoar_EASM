package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// The network-service and cloud-endpoint checks that run after the web checks, inside the
// active checks: EASM-EXP-006, -008, -009, -010, EASM-DNS-010, -011, EASM-TLS-010 and
// EASM-CLOUD-006, -007. Findings are computed here and raised by applyActive.

// netKeyIP makes an address safe inside a colon-separated finding key.
func netKeyIP(ip string) string { return strings.ReplaceAll(ip, ":", "-") }

func netScope(ip string, port int) string { return fmt.Sprintf("net|%s|%d", netKeyIP(ip), port) }

// jsonShape summarises a JSON answer: "data" (an object or list with content), "small", "error", or "" when it is not JSON.
func jsonShape(h http.Header, body []byte) string {
	if !strings.Contains(strings.ToLower(h.Get("Content-Type")), "json") {
		return ""
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	switch x := v.(type) {
	case map[string]any:
		for _, k := range []string{"error", "errors", "message", "Message", "errorMessage"} {
			if _, bad := x[k]; bad && len(x) <= 3 {
				return "error"
			}
		}
		if len(x) >= 2 {
			return "data"
		}
	case []any:
		if len(x) >= 2 {
			return "data"
		}
	}
	return "small"
}

var lbSuffixes = []struct{ suffix, name string }{
	{".elb.amazonaws.com", "AWS Elastic Load Balancing"}, {".trafficmanager.net", "Azure Traffic Manager"},
	{".azurefd.net", "Azure Front Door"}, {".cloudapp.azure.com", "an Azure public IP / Application Gateway"},
}

var functionSuffixes = []struct{ suffix, name string }{
	{".on.aws", "an AWS Lambda function URL"}, {".execute-api.", "an AWS API Gateway endpoint"},
	{".run.app", "a Google Cloud Run service"}, {".cloudfunctions.net", "a Google Cloud Function"},
}

func endpointKind(names []string, list []struct{ suffix, name string }) string {
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		for _, s := range list {
			if strings.HasSuffix(n, s.suffix) || (strings.HasPrefix(s.suffix, ".") && strings.HasSuffix(s.suffix, ".") && strings.Contains(n, s.suffix)) {
				return s.name
			}
		}
	}
	return ""
}

// gatherNet runs the checks. intel supplies the open ports exposure data reports.
func (s *Scanner) gatherNet(ctx context.Context, t *Target, results map[string]*HostResult, wildcard map[string]struct{},
	asns map[string]*ASNInfo, intel *intelData, d *activeData, pr *Prober) {
	cfg := s.cfg.Active
	owned := func(ip string) bool {
		if !pr.allow(net.ParseIP(ip)) {
			return false
		}
		if t.hasOwnershipRules() && !cfg.Foreign {
			info := asns[ip]
			return info != nil && t.owns(info)
		}
		return true
	}
	hostOf := map[string]string{}
	var ips []string
	for _, h := range sortedKeys(results) {
		hr := results[h]
		if hr == nil || hr.NX {
			continue
		}
		for _, rt := range []string{"A", "AAAA"} {
			for _, ip := range hr.Records[rt] {
				if _, w := wildcard[ip]; w {
					continue
				}
				if _, seen := hostOf[ip]; !seen {
					hostOf[ip] = h
					ips = append(ips, ip)
				}
			}
		}
	}
	add := func(key, kind, sev, host, detail string) {
		d.extra = append(d.extra, dnsxFinding{key: key, kind: kind, sev: sev, host: host, detail: detail})
	}
	netKey := func(kind, ip string, port int, slug string) string {
		k := fmt.Sprintf("net:%s:%s:%d", kind, netKeyIP(ip), port)
		if slug != "" {
			k += ":" + slug
		}
		return k
	}
	where := func(ip string) string {
		if h := hostOf[ip]; h != "" {
			return fmt.Sprintf("%s (%s)", h, ip)
		}
		return ip
	}

	if cfg.Services {
		// Open ports from exposure data, for the datastore and resolver checks.
		open := map[string]map[int]bool{}
		if intel != nil && intel.res != nil {
			for ip, bySrc := range intel.res.Intel {
				for _, in := range bySrc {
					for _, sv := range in.Services {
						if open[ip] == nil {
							open[ip] = map[int]bool{}
						}
						open[ip][sv.Port] = true
					}
				}
			}
		}
		for _, ip := range sortedKeys(open) {
			if !owned(ip) || ctx.Err() != nil {
				continue
			}
			for _, port := range sortedIntKeys(open[ip]) {
				chk, ok := datastoreChecks[port]
				if !ok {
					continue
				}
				what, err := chk.Check(pr, ctx, ip, port)
				if err != nil {
					continue
				}
				d.scopes[netScope(ip, port)] = true
				if what != "" {
					add(netKey("unauthenticated-datastore", ip, port, ""), "unauthenticated-datastore", "high", hostOf[ip],
						fmt.Sprintf("%s on %s port %d: %s.", chk.Name, where(ip), port, what))
				}
			}
			if open[ip][53] {
				if yes, err := pr.openResolver(ctx, ip); err == nil {
					d.scopes[netScope(ip, 53)] = true
					if yes {
						add(netKey("dns-open-resolver", ip, 53, ""), "dns-open-resolver", "medium", hostOf[ip],
							fmt.Sprintf("%s resolves names for anyone on the internet (it answered a recursive question for example.com). Open resolvers are used to amplify denial-of-service attacks and leak what your network looks up.", where(ip)))
					}
				}
			}
		}

		// Zone transfer from the domain's own nameservers, where they are on its own networks.
		if rr := results[t.Domain]; rr != nil {
			for _, ns := range rr.Records["NS"] {
				nsIPs, _, err := s.res.Addrs(ctx, ns)
				if err != nil {
					continue
				}
				for _, ip := range nsIPs {
					if !owned(ip) || ctx.Err() != nil {
						continue
					}
					n, err := pr.zoneTransfer(ctx, ip, t.Domain)
					d.scopes[netScope(ip, 53)+"|axfr"] = err == nil || n == 0
					if n > 0 {
						add(netKey("dns-zone-transfer", ip, 53, "axfr"), "dns-zone-transfer", "high", t.Domain,
							fmt.Sprintf("The nameserver %s (%s) hands a full copy of the %s zone to anyone who asks (AXFR): it sent %d records, listing every host name, including ones never meant to be found.", ns, ip, t.Domain, n))
					}
				}
			}
		}

		// Web services: NTLM details, weak ciphers, cloud endpoints.
		for _, wr := range d.results {
			if ctx.Err() != nil {
				break
			}
			k := func(kind string) string { return fmt.Sprintf("web:%s:%s:%d", kind, wr.Host, wr.Port) }
			if in, path, ok := pr.ntlmInfo(ctx, wr); ok && in.String() != "" {
				add(k("ntlm-info-leak"), "ntlm-info-leak", "low", wr.Host, fmt.Sprintf("%s%s offers NTLM sign-in, and its challenge reveals %s.",
					strings.TrimSuffix(wr.URL(), "/"), path, in.String()))
			}
			if wr.Scheme == "https" {
				weak, err := pr.weakCiphers(ctx, wr.Host, wr.IP, wr.Port)
				if err != nil {
					delete(d.scopes, webScope(wr.Host, wr.Port)) // not fully checked this time
				} else if len(weak) > 0 {
					add(k("tls-weak-cipher"), "tls-weak-cipher", "medium", wr.Host, fmt.Sprintf("%s:%d agrees to weak cipher suites: %s.", wr.Host, wr.Port, strings.Join(weak, ", ")))
				}
			}
			names := append([]string{wr.Host}, results[wr.Host].cnames()...)
			if lb := endpointKind(names, lbSuffixes); lb != "" && (wr.Status == 502 || wr.Status == 503 || wr.Status == 504) {
				add(k("orphaned-load-balancer"), "orphaned-load-balancer", "medium", wr.Host, fmt.Sprintf("%s points at %s, which answers HTTP %d: it has no healthy backend. "+
					"A load balancer or traffic manager left without targets is often a forgotten service, and on some platforms its name can be re-used by someone else.", wr.URL(), lb, wr.Status))
			}
			if fn := endpointKind(names, functionSuffixes); fn != "" && wr.Status == http.StatusOK && (wr.RootJSON == "data" || wr.RootJSON == "small") {
				sev := "medium"
				if wr.RootJSON == "data" {
					sev = "high"
				}
				add(k("exposed-function-url"), "exposed-function-url", sev, wr.Host, fmt.Sprintf("%s is %s that answers with JSON data (HTTP 200) without any authentication.", wr.URL(), fn))
			}
		}
		s.originBypass(ctx, results, wildcard, owned, d, pr, add)
	}

	if cfg.SNMP {
		// A device that does not run SNMP never answers, so each address waits out the
		// timeout: ask them in parallel, within the active checks' concurrency.
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, max(1, cfg.Concurrency))
		n := 0
		for _, ip := range ips {
			if !owned(ip) || ctx.Err() != nil || n >= cfg.MaxHosts {
				continue
			}
			n++
			sem <- struct{}{}
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				defer func() { <-sem }()
				comm, descr, err := pr.snmpDefault(ctx, ip)
				if err != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				d.scopes[netScope(ip, 161)] = true
				if comm != "" {
					what := ""
					if descr != "" {
						what = fmt.Sprintf(" (it describes itself as %q)", truncate(descr, 120))
					}
					add(netKey("snmp-default-creds", ip, 161, ""), "snmp-default-creds", "high", hostOf[ip],
						fmt.Sprintf("%s answers SNMP with the default community %q%s. Anyone can read its configuration and network details; with %q often also change them.", where(ip), comm, what, "private"))
				}
			}(ip)
		}
		wg.Wait()
	}
}

// cnames returns a host's CNAME targets (nil-safe).
func (h *HostResult) cnames() []string {
	if h == nil {
		return nil
	}
	return h.Records["CNAME"]
}

// originBypass (EASM-EXP-008) looks for a site behind a CDN that one of the organisation's own
// addresses also serves directly, which lets an attacker go around the CDN's WAF.
func (s *Scanner) originBypass(ctx context.Context, results map[string]*HostResult, wildcard map[string]struct{}, owned func(string) bool,
	d *activeData, pr *Prober, add func(key, kind, sev, host, detail string)) {
	if !s.cfg.Intel.Cloud || s.feeds == nil {
		return
	}
	var origins []string
	seen := map[string]bool{}
	for _, wr := range d.results {
		if c, ok := s.feeds.Cloud(wr.IP); (!ok || !c.CDN) && owned(wr.IP) && !seen[wr.IP] {
			seen[wr.IP] = true
			origins = append(origins, wr.IP)
		}
	}
	sort.Strings(origins)
	if len(origins) > 10 {
		origins = origins[:10]
	}
	if len(origins) == 0 {
		return
	}
	checked := 0
	for _, h := range sortedKeys(results) {
		hr := results[h]
		if hr == nil || hr.NX || checked >= 10 || ctx.Err() != nil {
			continue
		}
		var cdnIP, cdnName string
		all := true
		for _, ip := range hr.Records["A"] {
			if _, w := wildcard[ip]; w {
				all = false
				break
			}
			c, ok := s.feeds.Cloud(ip)
			if !ok || !c.CDN {
				all = false
				break
			}
			cdnIP, cdnName = ip, c.Provider
		}
		if !all || cdnIP == "" {
			continue
		}
		checked++
		base, err := pr.fetch(ctx, "https", h, cdnIP, 443, "/")
		if err != nil || base.Status < 200 || base.Status >= 300 {
			continue
		}
		bt, bl := pageTitle(base.Body), len(base.Body)
		for _, ip := range origins {
			r, err := pr.fetch(ctx, "https", h, ip, 443, "/")
			if err != nil || r.Status != base.Status {
				continue
			}
			same := string(r.Body) == string(base.Body)
			if !same && bt != "" && pageTitle(r.Body) == bt && bl > 0 {
				diff := len(r.Body) - bl
				if diff < 0 {
					diff = -diff
				}
				same = diff*5 <= bl // within 20%
			}
			if same {
				add(fmt.Sprintf("web:waf-origin-bypass:%s:443:%s", h, netKeyIP(ip)), "waf-origin-bypass", "high", h,
					fmt.Sprintf("%s is served through %s, but %s, one of your own addresses, serves the same site directly when asked for %s. "+
						"An attacker can send requests straight to it and skip the CDN's protection (WAF, rate limits, DDoS filtering).", h, cdnName, ip, h))
				break
			}
		}
	}
}
