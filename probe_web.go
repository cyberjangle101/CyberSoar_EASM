package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Web checks that read the answers the prober already gets, plus a handful of extra read-only
// requests: EASM-WEB-005 to WEB-011 and EASM-TLS-011. Like the rest of the prober, they only
// reach addresses the address policy allows.

// ---- EASM-WEB-005: what a directory listing offers

var riskyFileRe = regexp.MustCompile(`(?i)href="([^"?#]+\.(zip|tar|tgz|gz|bz2|xz|7z|rar|sql|bak|backup|dump|db|sqlite|sqlite3|mdb|old|orig))"`)

// riskyListed returns up to five archives, dumps or backups a listing links to.
func riskyListed(body []byte) []string {
	var out []string
	for _, m := range riskyFileRe.FindAllSubmatch(body, -1) {
		if n := string(m[1]); !strings.Contains(n, "://") {
			out = append(out, n)
		}
		if len(out) == 5 {
			break
		}
	}
	return dedupe(out)
}

// ---- EASM-WEB-010: session cookies without Secure or HttpOnly

var sessionCookieRe = regexp.MustCompile(`(?i)(sess|sid$|^sid|auth|token|jwt|login|remember|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|_session$|\.aspxauth)`)

// insecureCookies lists the session or sign-in cookies a response sets without the flags that protect them.
func insecureCookies(h http.Header, https bool) []string {
	var out []string
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if !sessionCookieRe.MatchString(c.Name) || c.MaxAge < 0 {
			continue // not a session cookie, or one being deleted
		}
		var miss []string
		if https && !c.Secure {
			miss = append(miss, "no Secure")
		}
		if !c.HttpOnly {
			miss = append(miss, "no HttpOnly")
		}
		if len(miss) > 0 {
			out = append(out, c.Name+" ("+strings.Join(miss, ", ")+")")
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

// ---- EASM-WEB-011: baseline security headers

func missingHeaders(h http.Header) (missing []string, noFrame bool) {
	csp := strings.ToLower(h.Get("Content-Security-Policy"))
	if csp == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		missing = append(missing, "X-Frame-Options (or CSP frame-ancestors)")
		noFrame = true
	}
	if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		missing = append(missing, "X-Content-Type-Options: nosniff")
	}
	return missing, noFrame
}

// ---- EASM-WEB-009: scripts loaded from other domains

var scriptSrcRe = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)

// scriptHosts lists the hosts outside the site's own registrable domain that the page loads scripts from.
func scriptHosts(body []byte, host string) []string {
	own := registrable(host)
	var out []string
	for _, m := range scriptSrcRe.FindAllSubmatch(body, 50) {
		src := string(m[1])
		if strings.HasPrefix(src, "//") {
			src = "https:" + src
		}
		u, err := url.Parse(src)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if r := registrable(h); r != "" && r != own {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

// ---- EASM-WEB-008: version headers, debuggers and debug error pages

var versionDigitRe = regexp.MustCompile(`\d+\.\d+`)

// versionHeaders describes headers that announce exact software versions ("" = none).
func versionHeaders(h http.Header) string {
	var got []string
	for _, k := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
		if v := h.Get(k); v != "" && versionDigitRe.MatchString(v) {
			got = append(got, k+": "+truncate(v, 60))
		}
	}
	if len(got) == 0 {
		return ""
	}
	return "the response announces exact software versions (" + strings.Join(got, "; ") + "), which tells an attacker which known vulnerabilities to try"
}

// debugPages are signs that an application runs in debug mode. A made-up path is fetched to
// see the error page; the others are well-known debug endpoints.
var debugPages = []struct {
	Path, Needle, Why, Severity string
}{
	{"", "Werkzeug Debugger", "the Werkzeug interactive debugger is switched on; anyone who reaches it can run code on the server", "high"},
	{"", "<code>DEBUG = True</code>", "the Django debug error page is switched on and shows settings, paths and request data", "high"},
	{"", "Whoops! There was an error.", "the Whoops debug error page is switched on and shows the environment and source code", "high"},
	{"", "Server Error in '/' Application", "the ASP.NET detailed error page is shown, with a stack trace and versions", "medium"},
	{"/_ignition/health-check", `"can_execute_commands":true`, "Laravel Ignition is reachable with debug commands enabled, which has allowed remote code execution (CVE-2021-3129)", "high"},
	{"/_profiler/", "Symfony Profiler", "the Symfony profiler is public and shows every request, with headers, cookies and configuration", "high"},
}

func (p *Prober) checkDebug(ctx context.Context, wr *WebResult, scheme, host, ip string, port int) {
	missing := "/easm-check-" + randHex(6)
	for _, dp := range debugPages {
		if ctx.Err() != nil {
			return
		}
		path := dp.Path
		if path == "" {
			path = missing
		}
		r, err := p.fetch(ctx, scheme, host, ip, port, path)
		if err != nil {
			continue
		}
		if strings.Contains(string(r.Body), dp.Needle) {
			wr.Debug = append(wr.Debug, PathHit{Path: path, Why: dp.Why, Severity: dp.Severity})
		}
	}
}

// ---- EASM-WEB-006: API descriptions, Swagger UI and GraphQL introspection

var schemaPaths = []struct {
	Path, Why, Severity string
	Test                func(b []byte, h http.Header) bool
}{
	{"/swagger.json", "an API description is public and maps every endpoint for an attacker", "low", isAPISpec},
	{"/openapi.json", "an API description is public and maps every endpoint for an attacker", "low", isAPISpec},
	{"/v3/api-docs", "an API description is public and maps every endpoint for an attacker", "low", isAPISpec},
	{"/swagger-ui.html", "Swagger UI is public, so anyone can browse and call the API from the browser", "medium", isSwaggerUI},
	{"/swagger-ui/", "Swagger UI is public, so anyone can browse and call the API from the browser", "medium", isSwaggerUI},
	{"/api-docs/", "Swagger UI is public, so anyone can browse and call the API from the browser", "medium", isSwaggerUI},
}

func isSwaggerUI(b []byte, h http.Header) bool {
	s := string(b)
	return strings.Contains(strings.ToLower(h.Get("Content-Type")), "html") && strings.Contains(s, "swagger-ui")
}

// graphQLIntrospection is a read-only query: it asks the schema for its type names.
const graphQLIntrospection = `{"query":"query EasmIntrospection { __schema { queryType { name } types { name } } }"}`

// devHost is true for names that look like developer or test systems, where a public API schema is less surprising.
func devHost(host string) bool {
	first := strings.SplitN(host, ".", 2)[0]
	for _, w := range []string{"dev", "test", "staging", "stage", "sandbox", "qa", "uat", "docs", "developer", "api-docs"} {
		if first == w || strings.HasPrefix(first, w+"-") || strings.HasSuffix(first, "-"+w) {
			return true
		}
	}
	return false
}

func (p *Prober) checkSchemas(ctx context.Context, wr *WebResult, scheme, host, ip string, port int) {
	for _, sp := range schemaPaths {
		if ctx.Err() != nil {
			return
		}
		r, err := p.fetch(ctx, scheme, host, ip, port, sp.Path)
		if err != nil || r.Status != http.StatusOK || !sp.Test(r.Body, r.Header) {
			continue
		}
		sev := sp.Severity
		if devHost(host) {
			sev = "low"
		}
		wr.Schemas = append(wr.Schemas, PathHit{Path: sp.Path, Why: sp.Why, Severity: sev})
	}
	for _, path := range []string{"/graphql", "/api/graphql"} {
		if ctx.Err() != nil {
			return
		}
		r, err := p.fetchWith(ctx, http.MethodPost, scheme, host, ip, port, path, map[string]string{"Content-Type": "application/json"}, []byte(graphQLIntrospection))
		if err != nil || r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"__schema"`) || !strings.Contains(string(r.Body), `"types"`) {
			continue
		}
		sev := "medium"
		if devHost(host) {
			sev = "low"
		}
		wr.Schemas = append(wr.Schemas, PathHit{Path: path, Why: "GraphQL introspection is enabled, so anyone can download the full schema: every query, mutation and field", Severity: sev})
		break
	}
}

// ---- EASM-WEB-007: CORS that trusts any origin with credentials

func (p *Prober) checkCORS(ctx context.Context, wr *WebResult, scheme, host, ip string, port int) {
	origin := "https://easm-cors-check-" + randHex(6) + ".example"
	r, err := p.fetchWith(ctx, http.MethodGet, scheme, host, ip, port, "/", map[string]string{"Origin": origin}, nil)
	if err != nil {
		return
	}
	wr.CORSKnown = true
	if r.Header.Get("Access-Control-Allow-Origin") == origin && strings.EqualFold(strings.TrimSpace(r.Header.Get("Access-Control-Allow-Credentials")), "true") {
		wr.CORS = origin
	}
}

// ---- EASM-MAIL-017: the MTA-STS policy file

var mtaSTSModes = map[string]bool{"enforce": true, "testing": true, "none": true}

// validMTASTSPolicy checks a policy file against RFC 8461 section 3.2 ("" = valid).
func validMTASTSPolicy(body string) string {
	kv := map[string][]string{}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			k = strings.ToLower(strings.TrimSpace(k))
			kv[k] = append(kv[k], strings.TrimSpace(v))
		}
	}
	switch {
	case len(kv["version"]) == 0 || kv["version"][0] != "STSv1":
		return "it does not start with version: STSv1"
	case len(kv["mode"]) == 0 || !mtaSTSModes[kv["mode"][0]]:
		return "it has no valid mode (enforce, testing or none)"
	case len(kv["max_age"]) == 0 || !maxAgeRe.MatchString(kv["max_age"][0]):
		return "it has no valid max_age"
	case kv["mode"][0] != "none" && len(kv["mx"]) == 0:
		return "it lists no mx: lines, so no mail server is allowed"
	}
	return ""
}

var maxAgeRe = regexp.MustCompile(`^\d{1,10}$`)

// mtaSTSProblem fetches the domain's MTA-STS policy the way a sending server does (HTTPS with a
// valid certificate) and says what is wrong with it. ok is false when nothing could be concluded.
func (s *Scanner) mtaSTSProblem(ctx context.Context, root string) (problem string, ok bool) {
	pr := s.prober
	if pr == nil {
		pr = NewProber(s.cfg.Active)
	}
	host := "mta-sts." + root
	ips, nx, err := s.res.Addrs(ctx, host)
	switch {
	case err != nil:
		return "", false
	case nx || len(ips) == 0:
		return host + " does not exist in DNS", true
	}
	ip := ips[0]
	if !pr.allow(net.ParseIP(ip)) {
		return "", false
	}
	ti, err := pr.tlsInfo(ctx, host, ip, 443)
	if err != nil {
		return "", false // could not connect: may be passing, so no conclusion
	}
	if ti.Problem != "" {
		return "its HTTPS certificate is not valid (" + ti.ProblemText + "), and senders must refuse such a policy", true
	}
	r, err := pr.fetch(ctx, "https", host, ip, 443, "/.well-known/mta-sts.txt")
	switch {
	case err != nil || r.Status >= 500:
		return "", false
	case r.Status != http.StatusOK:
		return fmt.Sprintf("the file answers HTTP %d", r.Status), true
	}
	if why := validMTASTSPolicy(string(r.Body)); why != "" {
		return why, true
	}
	return "", true
}

// ---- EASM-TLS-011: the certificate a server shows without SNI

// defaultCertNames returns the names on the certificate an address presents to a client that
// does not say which site it wants. It uses the prober's one handshake (an empty host name
// sends no SNI), so this check adds no TLS configuration of its own.
func (p *Prober) defaultCertNames(ctx context.Context, ip string, port int) ([]string, error) {
	c, err := p.handshake(ctx, "", ip, port, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	st := c.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, nil
	}
	leaf := st.PeerCertificates[0]
	names := append([]string{}, leaf.DNSNames...)
	if leaf.Subject.CommonName != "" {
		names = append(names, leaf.Subject.CommonName)
	}
	for i, n := range names {
		names[i] = strings.ToLower(strings.TrimSuffix(n, "."))
	}
	sort.Strings(names)
	return dedupe(names), nil
}

// internalName is true for a name that only makes sense inside a network: a single label, or a
// top-level domain that is not a public one (corp, local, lan, internal and the like).
func internalName(n string) bool {
	n = strings.TrimPrefix(n, "*.")
	switch n {
	case "", "localhost", "localhost.localdomain":
		return false
	}
	if !strings.Contains(n, ".") {
		return strings.ContainsAny(n, "abcdefghijklmnopqrstuvwxyz")
	}
	suffix, icann := publicsuffix.PublicSuffix(n)
	return !icann && !strings.Contains(suffix, ".")
}
