package main

// The rule index: every finding the agent can raise, with a stable rule ID, how its
// evidence is gathered, its severity and exactly what triggers it. It is the source of
// docs/RULES.md (rules_doc_test.go regenerates and checks that file), together with
// the detection tables the rules use: sensitivePaths, portalSigs, defaultPages,
// riskyPorts, takeoverSuffixes, datastoreSigs and the rest. Every kind in
// findingCatalog must have an entry here, and the test fails if one is missing.

// How a rule gathers its evidence.
const (
	modePassiveDNS = "Passive: DNS"
	modeActive     = "Active: connects to the organisation's own servers (opt-in)"
	modeIntel      = "Third-party intelligence (needs a second source to be trusted)"
	modeRegistry   = "Passive: registration data (RDAP)"
	modeOSINT      = "Passive: public sources (OSINT)"
)

// Rule categories, in the order the reference lists them.
var ruleCategories = []string{
	"DNS and domain", "Email authentication", "TLS and HTTPS", "Web exposure", "Cloud and storage",
	"Exposure intelligence", "Threat intelligence (off by default)",
}

type ruleMeta struct {
	ID, Category, Mode, Severity, Trigger string
}

var ruleIndex = map[string]ruleMeta{
	// DNS and domain
	"dangling-cname": {"EASM-DNS-001", "DNS and domain", modePassiveDNS, "High on a claim-able platform (see takeover platforms, plus the can-i-take-over-xyz services that report NXDOMAIN), otherwise Low",
		"A CNAME record whose target does not exist (NXDOMAIN)."},
	"private-ip": {"EASM-DNS-002", "DNS and domain", modePassiveDNS, "Low",
		"An A/AAAA record in public DNS points at a private, loopback or other non-public address."},
	"asn-unexpected": {"EASM-DNS-003", "DNS and domain", modePassiveDNS, "High",
		"An address the domain's names resolve to is announced by a network (ASN) or organisation outside the expected ownership configured for the domain."},
	"email-auth/no-caa":    {"EASM-DNS-004", "DNS and domain", modePassiveDNS, "Low", "No CAA record at the domain."},
	"email-auth/no-dnssec": {"EASM-DNS-005", "DNS and domain", modePassiveDNS, "Low", "No DS record for the domain at its parent zone."},
	"subdomain-takeover": {"EASM-DNS-007", "DNS and domain", modeActive, "High",
		"A name's CNAME points at a service listed as claimable by can-i-take-over-xyz, and its home page shows that service's 'nothing here' text."},
	"domain-expiry": {"EASM-DNS-006", "DNS and domain", modeRegistry, "High within 14 days (or expired), Medium within 30, Low within 60",
		"The registration expiry date in RDAP is close."},
	"dangling-ns": {"EASM-DNS-008", "DNS and domain", modePassiveDNS, "High when the nameservers' domain is not registered, or when every delegated nameserver answers REFUSED or SERVFAIL, is not authoritative for the zone or does not exist; Medium when the nameservers' domain is registered but withdrawn from DNS",
		"A zone is delegated (NS records, read from the domain's own nameservers when resolvers return SERVFAIL) to nameservers whose domain has no DNS delegation (NXDOMAIN; RDAP tells unregistered from on hold), or none of which serves the zone when asked directly for its SOA."},
	"dangling-mx": {"EASM-DNS-009", "DNS and domain", modePassiveDNS, "High when the mail server's domain is not registered, Medium when it is registered but withdrawn from DNS, Low when only the mail server name does not exist",
		"An MX record points at a mail server whose domain has no DNS delegation (NXDOMAIN; RDAP tells unregistered from on hold), or at a name that does not exist."},
	"domain-unlocked": {"EASM-DNS-012", "DNS and domain", modeRegistry, "Medium",
		"The RDAP status list of a generic top-level domain (not two-letter country codes, many of which do not use these statuses) has neither clientTransferProhibited nor serverTransferProhibited."},
	"dns-zone-transfer": {"EASM-DNS-010", "DNS and domain", modeActive, "High",
		"With network-service checks on: one of the domain's nameservers, on the domain's own networks, answers a zone transfer (AXFR over TCP) with records."},
	"dns-open-resolver": {"EASM-DNS-011", "DNS and domain", modeActive, "Medium",
		"With network-service checks on: an address of the organisation whose port 53 is reported open answers a recursive question for example.com with an answer and the RA flag, without being authoritative."},
	"dns-wildcard": {"EASM-DNS-013", "DNS and domain", modePassiveDNS, "Low",
		"Randomly generated names under the domain resolve to addresses (wildcard DNS)."},

	// Email authentication
	"email-auth/no-spf":               {"EASM-MAIL-001", "Email authentication", modePassiveDNS, "Medium", "No TXT record starting v=spf1 at the domain apex."},
	"email-auth/spf-multiple":         {"EASM-MAIL-002", "Email authentication", modePassiveDNS, "High", "More than one SPF record at the apex."},
	"email-auth/spf-permissive":       {"EASM-MAIL-003", "Email authentication", modePassiveDNS, "High", "The SPF record ends in +all or all."},
	"email-auth/spf-neutral":          {"EASM-MAIL-004", "Email authentication", modePassiveDNS, "Medium", "The SPF record ends in ?all."},
	"email-auth/spf-ptr":              {"EASM-MAIL-005", "Email authentication", modePassiveDNS, "Low", "The SPF record uses the ptr mechanism."},
	"email-auth/spf-too-many-lookups": {"EASM-MAIL-006", "Email authentication", modePassiveDNS, "Medium", "Evaluating SPF, including every include:, needs more than 10 DNS lookups."},
	"email-auth/no-dmarc":             {"EASM-MAIL-007", "Email authentication", modePassiveDNS, "Medium", "No TXT record starting v=DMARC1 at _dmarc.<domain>."},
	"email-auth/dmarc-p-none":         {"EASM-MAIL-008", "Email authentication", modePassiveDNS, "Low", "The DMARC policy is p=none."},
	"email-auth/dmarc-sp-none":        {"EASM-MAIL-009", "Email authentication", modePassiveDNS, "Medium", "The DMARC record sets sp=none for subdomains."},
	"email-auth/dmarc-pct":            {"EASM-MAIL-010", "Email authentication", modePassiveDNS, "Low", "The DMARC record has pct below 100."},
	"email-auth/dmarc-no-reports":     {"EASM-MAIL-011", "Email authentication", modePassiveDNS, "Low", "The DMARC record has no rua= reporting address."},
	"email-auth/dkim-not-found":       {"EASM-MAIL-012", "Email authentication", modePassiveDNS, "Low", "No DKIM key at any of the common selector names (see DKIM selectors)."},
	"email-auth/dkim-weak-key":        {"EASM-MAIL-013", "Email authentication", modePassiveDNS, "Medium", "A DKIM key is shorter than 1024 bits."},
	"email-auth/dkim-short-key":       {"EASM-MAIL-014", "Email authentication", modePassiveDNS, "Low", "A DKIM key is exactly 1024 bits."},
	"email-auth/no-mta-sts":           {"EASM-MAIL-015", "Email authentication", modePassiveDNS, "Low", "No TXT record at _mta-sts.<domain>."},
	"email-auth/dnsbl-listed": {"EASM-MAIL-018", "Email authentication", modePassiveDNS, "High when a mail address (an MX server or a single SPF ip4: entry) is listed, Medium when only the domain's or www's web address is",
		"With spam blocklists switched on (off by default): an IPv4 address of the domain's mail servers, SPF entries, domain or www is listed on a blocklist (see spam blocklists): the lookup returns 127.0.0.x."},
	"email-auth/mta-sts-broken": {"EASM-MAIL-017", "Email authentication", modeActive, "Medium",
		"With active checks on and a v=STSv1 record published: mta-sts.<domain> does not exist, its HTTPS certificate is not valid, /.well-known/mta-sts.txt does not answer 200, or the file lacks version: STSv1, a valid mode, max_age, or (unless mode is none) an mx: line."},
	"email-auth/no-tls-rpt": {"EASM-MAIL-016", "Email authentication", modePassiveDNS, "Low", "No TXT record at _smtp._tls.<domain>."},

	// TLS and HTTPS
	"tls-expired": {"EASM-TLS-001", "TLS and HTTPS", modeActive, "High", "The certificate presented on an HTTPS port has expired."},
	"tls-expiring": {"EASM-TLS-002", "TLS and HTTPS", modeActive, "High within 7 days, Medium within 30",
		"The certificate expires within 30 days."},
	"tls-hostname":       {"EASM-TLS-003", "TLS and HTTPS", modeActive, "Medium", "The certificate does not cover the host name it was served for."},
	"tls-untrusted":      {"EASM-TLS-004", "TLS and HTTPS", modeActive, "Medium", "The certificate is self-signed, from an untrusted authority, has an incomplete chain, or is not yet valid."},
	"tls-legacy":         {"EASM-TLS-005", "TLS and HTTPS", modeActive, "Medium", "A handshake offering only TLS 1.0 or only TLS 1.1 succeeds."},
	"tls-weak-key":       {"EASM-TLS-006", "TLS and HTTPS", modeActive, "Medium", "The certificate key is RSA under 2048 bits or ECDSA under 256 bits."},
	"tls-weak-signature": {"EASM-TLS-007", "TLS and HTTPS", modeActive, "Medium", "The certificate is signed with SHA-1, MD5 or MD2."},
	"hsts-missing":       {"EASM-TLS-008", "TLS and HTTPS", modeActive, "Low", "An HTTPS site with a valid certificate answers 2xx without a Strict-Transport-Security header."},
	"no-https-redirect": {"EASM-TLS-009", "TLS and HTTPS", modeActive, "Low",
		"Port 80 answers with content instead of redirecting to https://, while the same host serves HTTPS."},
	"tls-weak-cipher": {"EASM-TLS-010", "TLS and HTTPS", modeActive, "Medium",
		"With network-service checks on: a TLS 1.2 ClientHello offering only weak suites (see weak cipher suites) is answered with a ServerHello choosing one of them. Up to four are named."},
	"tls-sni-hostname-leak": {"EASM-TLS-011", "TLS and HTTPS", modeActive, "Low",
		"An address serving HTTPS on 443, asked without SNI, shows a certificate naming an internal-looking host (a single label, or a top-level domain that is not public, such as corp, local, lan or internal) or a name under the domain that the scan has not seen."},
	"ct-unauthorized-ca": {"EASM-TLS-012", "TLS and HTTPS", modeOSINT, "High",
		"A certificate in Certificate Transparency, issued in the last 30 days and still valid, comes from an authority (recognised from its issuer name, see CAA authorities) that the CAA records governing one of its names do not allow (issuewild for wildcard names). Names with no CAA record up to the domain are not checked."},
	"shadow-it-ct-subdomain": {"EASM-TLS-013", "TLS and HTTPS", modeOSINT, "Medium when the active web check reached a web service on it, otherwise Low",
		"After the baseline scan, a host name first listed by Certificate Transparency (crt.sh or CertSpotter) resolves to an address that is not a wildcard answer."},

	// Web exposure
	"login-portal": {"EASM-WEB-001", "Web exposure", modeActive, "Per product (see login portals): High for infrastructure consoles, Medium for remote-access gateways, webmail/SSO and monitoring or collaboration tools, Low for website sign-ins",
		"The home page, or a product's well-known sign-in page, is recognised as one of the login portals listed below."},
	"exposed-path": {"EASM-WEB-002", "Web exposure", modeActive, "Per file: High, Medium or Low (see sensitive files)",
		"A well-known sensitive file or page answers 200 and its content passes the file's own test (and is not the site's catch-all page)."},
	"default-page": {"EASM-WEB-003", "Web exposure", modeActive, "Low",
		"The home page answers 200 with a web server's default page (see default pages)."},
	"no-security-txt": {"EASM-WEB-004", "Web exposure", modeActive, "Low",
		"The domain or www over HTTPS has no /.well-known/security.txt with a Contact: line."},
	"directory-listing": {"EASM-WEB-005", "Web exposure", modeActive, "High when the listing links to archives, dumps or backups (.zip, .tar, .sql, .bak, .dump, .db and similar), otherwise Medium",
		"The home page is a web server's directory listing (\"Index of /\")."},
	"exposed-api-schema": {"EASM-WEB-006", "Web exposure", modeActive, "Medium for Swagger UI and GraphQL introspection, Low for an API description file; Low on hosts named like developer or test systems (dev, test, staging, qa, uat, sandbox, docs)",
		"With sensitive-path checks on: an OpenAPI/Swagger description or Swagger UI answers 200 (see API schema paths), or a read-only GraphQL introspection query to /graphql or /api/graphql returns the schema's types."},
	"cors-credential-leak": {"EASM-WEB-007", "Web exposure", modeActive, "High",
		"A request to / with Origin: https://easm-cors-check-<random>.example is answered with that exact origin in Access-Control-Allow-Origin and Access-Control-Allow-Credentials: true."},
	"debug-mode-enabled": {"EASM-WEB-008", "Web exposure", modeActive, "Per sign (see debug signs): High for interactive debuggers and environment dumps, Medium for detailed error pages; Low for headers announcing exact versions",
		"X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version or X-Generator carries a version number; or, with sensitive-path checks on, a made-up path or a debug endpoint shows a debugger or debug error page."},
	"second-order-script-takeover": {"EASM-WEB-009", "Web exposure", modeActive, "High",
		"The home page loads a <script src> from a domain outside the site's own whose registrable domain has no DNS delegation (NXDOMAIN; RDAP tells unregistered from on hold)."},
	"insecure-auth-cookie": {"EASM-WEB-010", "Web exposure", modeActive, "Medium on a page recognised as a login portal (EASM-WEB-001), otherwise Low",
		"The home page sets a cookie whose name looks like a session or sign-in cookie (sess, sid, auth, token, jwt, login, remember, PHPSESSID, JSESSIONID and similar) without HttpOnly, or over HTTPS without Secure."},
	"secret-in-page": {"EASM-WEB-012", "Web exposure", modeActive, "High for private keys and cloud, payment, code-hosting, messaging and AI service keys; Medium for a Slack webhook; Low for a Google API key",
		"With sensitive-path checks on: the home page or one of the first five of the site's own scripts contains a token in a format that is secret by itself (see secret formats). Only the token's type, a masked form and a hash are stored."},
	"missing-security-headers": {"EASM-WEB-011", "Web exposure", modeActive, "Medium when a login portal (EASM-WEB-001) can be framed (no X-Frame-Options or CSP frame-ancestors), otherwise Low",
		"A 2xx HTML home page lacks Content-Security-Policy, X-Frame-Options (or CSP frame-ancestors), or X-Content-Type-Options: nosniff."},

	// Cloud and storage
	"bucket-public": {"EASM-CLOUD-001", "Cloud and storage", modeActive, "High; Medium for a bucket the site only links to whose name does not carry the domain's name (it may be a supplier's)",
		"With storage checks on: a bucket or container that a name points at, or that the home page or the site's own scripts link to, lists its contents to anyone. Checked on Amazon S3, Google Cloud Storage, DigitalOcean Spaces, Alibaba Cloud OSS, Azure Blob Storage (containers) and Firebase Storage."},
	"bucket-takeover": {"EASM-CLOUD-002", "Cloud and storage", modeActive, "High",
		"With storage checks on: a name points at, or the site loads files from, an Amazon S3, Google Cloud Storage, DigitalOcean Spaces or Alibaba Cloud OSS bucket that does not exist (NoSuchBucket). Bucket names on these are first come, first served."},
	"firebase-public": {"EASM-CLOUD-008", "Cloud and storage", modeActive, "High; Medium when the database is empty",
		"With storage checks on: a Firebase Realtime Database that the home page or the site's own scripts name answers a read of its top-level keys (/.json?shallow=true) without signing in."},
	"cloud-datastore": {"EASM-CLOUD-003", "Cloud and storage", modePassiveDNS, "Medium",
		"A name in public DNS is an alias for a managed database, cache or search service (see managed datastores)."},
	"orphaned-load-balancer": {"EASM-CLOUD-006", "Cloud and storage", modeActive, "Medium",
		"With network-service checks on: a name that is, or is an alias for, a cloud load balancer or traffic manager (see cloud endpoints) answers HTTP 502, 503 or 504."},
	"exposed-function-url": {"EASM-CLOUD-007", "Cloud and storage", modeActive, "High when the JSON answer carries data (two or more fields or items), otherwise Medium",
		"With network-service checks on: a name that is, or is an alias for, a serverless function URL or API endpoint (see cloud endpoints) answers 200 with JSON that is not an error, without any credentials."},

	// Exposure intelligence
	"exposed-service": {"EASM-EXP-001", "Exposure intelligence", modeIntel, "High for the high-risk ports, Medium for the other risky ports (see risky ports)",
		"An intelligence source reports one of the risky ports open on an address of the domain. Addresses on a CDN edge are skipped: tagged cdn by Shodan, or inside the published Cloudflare, Fastly, CloudFront or GitHub Pages ranges."},
	"known-vuln": {"EASM-EXP-002", "Exposure intelligence", modeIntel, "High with any CVE in CISA KEV, an EPSS of 50% or more, or 10 or more CVEs; otherwise Medium",
		"Shodan lists CVEs for the software versions seen on an address. CVEs in CISA KEV come first, then the highest FIRST EPSS scores. Shodan data alone leaves the finding unconfirmed (not counted or alerted): with active checks on, it is trusted when the agent's own web check sees the server announce the same product at the same version (Server or X-Powered-By header), or when an analyst confirms it."},
	"ip-flagged": {"EASM-EXP-003", "Exposure intelligence", modeIntel, "High when Shodan tags it, Medium when only SANS ISC reports it",
		"Shodan tags an address compromised, malware or doublepulsar, or SANS ISC shows it recently attacking: reports in the last 30 days from at least 100 DShield sensors, or a compromised-host feed listing (Emerging Threats compromised, CINS Army) seen in the last 30 days. Older or sparser ISC data is kept as evidence only. The two sources are independent, so together they make the finding trusted."},
	"tor-exit": {"EASM-EXP-005", "Exposure intelligence", "Passive: Tor Project exit list (download)", "Medium",
		"An address the domain's names resolve to is on the Tor Project's current exit-node list."},
	"unauthenticated-datastore": {"EASM-EXP-006", "Exposure intelligence", modeActive, "High; Medium for Prometheus, which exposes configuration and metrics rather than data",
		"With network-service checks on, for a port exposure data reports open on the organisation's own address: one read-only request (see datastore checks) is answered without credentials."},
	"waf-origin-bypass": {"EASM-EXP-008", "Exposure intelligence", modeActive, "High",
		"With network-service checks and cloud ranges on: a name whose addresses are all in a CDN's published ranges serves a 2xx home page through the CDN, and one of the organisation's own web addresses, asked for the same name over HTTPS, returns the same status and the same page (identical, or the same title and a length within 20%)."},
	"snmp-default-creds": {"EASM-EXP-009", "Exposure intelligence", modeActive, "High",
		"With the separate SNMP switch on (off by default): an SNMPv2c GET of sysDescr.0 to UDP 161 with the community public or private is answered."},
	"ntlm-info-leak": {"EASM-EXP-010", "Exposure intelligence", modeActive, "Low",
		"With network-service checks on: a web service answers an NTLM NEGOTIATE (on / and, for Microsoft-looking hosts, the usual Exchange, AD FS and certificate-services paths) with a challenge that names the Active Directory domain, computer or Windows build."},
	"eol-software": {"EASM-EXP-004", "Exposure intelligence", modeIntel, "Medium",
		"Shodan tags an address eol-os or eol-product."},

	// Threat intelligence: outside your own attack surface, so off unless switched on in Settings
	"lookalike-domain": {"EASM-BRAND-001", "Threat intelligence (off by default)", modeOSINT, "Medium when it accepts email (MX), otherwise Low",
		"A variation of the domain (see look-alike techniques), or a domain that contains a brand word or is one letter from a long one (brand watch: certificates issued in the last 30 days, from crt.sh, and an optional newly registered domains feed), is registered by someone else and accepts email or has a web address. Left out: names on the domain's own name servers, or whose name servers or mail servers are under the domain, or that point at its own web server; names served by parking or resale services; and names with neither mail nor web."},
	"phishing-clone": {"EASM-BRAND-004", "Threat intelligence (off by default)", "Active: visits look-alike sites (separate switch, off by default)", "High when the look-alike serves the same favicon (Shodan's MurmurHash3 hash) or a password field on a page with your title or name, Medium when only the page title matches",
		"For each reported look-alike with a web address: its home page and /favicon.ico (HTTPS, then HTTP) are compared with those of the domain or www."},
	"lookalike-tls-issued": {"EASM-BRAND-005", "Threat intelligence (off by default)", modeOSINT, "High (every reported look-alike accepts email or has a web address, see EASM-BRAND-001)",
		"Certificate Transparency (crt.sh) lists a still-valid certificate issued in the last 30 days for a reported look-alike (at most 10 look-alikes per scan)."},
	"dependency-confusion": {"EASM-BRAND-006", "Threat intelligence (off by default)", "Active: the organisation's own web services, then npm and PyPI (separate switch, off by default)", "High when the name does not exist on npm or PyPI; Medium for a scoped npm name (@scope/name), which is only claimable if the scope is not registered",
		"With active checks on: a package name found in the source maps of a site's own scripts (node_modules/...), its /package.json dependencies or its /requirements.txt does not exist on the public registry (npm or PyPI answers 404)."},
	"leaked-credentials": {"EASM-BRAND-002", "Threat intelligence (off by default)", modeOSINT, "High for 5 or more accounts in one breach, otherwise Medium",
		"Have I Been Pwned lists accounts at the domain in a breach (API key required)."},
	"repo-exposure": {"EASM-BRAND-003", "Threat intelligence (off by default)", modeOSINT, "Medium",
		"GitHub code search finds the domain near words such as password, secret or token (token required)."},
}

// dataSource is one external source, for the rules reference.
type dataSource struct {
	Name, Kind, Key, Sends, Default, Feeds string
}

// dataSources lists every external source the agent can use, what it is sent and
// which rules it feeds.
var dataSources = []dataSource{
	{"crt.sh", "Subdomain discovery (Certificate Transparency)", "None", "The domain name", "On", "Inventory; DNS-001...007 and every host-based rule"},
	{"CertSpotter", "Subdomain discovery (Certificate Transparency)", "None (100 requests/hour)", "The domain name", "On", "Inventory; a scan counts as complete when crt.sh or CertSpotter answered"},
	{"HackerTarget", "Subdomain discovery", "None (about 50 requests/day)", "The domain name", "On", "Inventory"},
	{"urlscan.io", "Subdomain discovery (public scans)", "None", "The domain name", "On", "Inventory"},
	{"Wayback Machine", "Subdomain discovery (archived URLs)", "None", "The domain name", "Off (slow)", "Inventory"},
	{"AlienVault OTX", "Subdomain discovery (passive DNS)", "Free key", "The domain name", "Off until a key is saved", "Inventory"},
	{"Anubis (jonlu.ca)", "Subdomain discovery", "None", "The domain name", "Off (blocks automated clients)", "Inventory"},
	{"Shodan DNS", "Subdomain discovery", "Shodan key (1 query credit per scan)", "The domain name", "Off", "Inventory"},
	{"VirusTotal", "Subdomain discovery", "Free key", "The domain name", "Off until a key is saved", "Inventory"},
	{"Public DNS resolvers (1.1.1.1, 8.8.8.8)", "DNS", "None", "Host names", "On", "All DNS and email rules"},
	{"DNS-over-HTTPS (Google, Cloudflare)", "DNS fallback when port 53 is blocked", "None", "Host names", "On", "All DNS and email rules"},
	{"Team Cymru", "IP to network owner (DNS)", "None", "IP addresses", "On", "DNS-003"},
	{"RIPEstat", "IP to network owner (fallback)", "None", "IP addresses", "On", "DNS-003"},
	{"Cloud and CDN IP ranges (AWS, Google Cloud, Cloudflare, Fastly, Oracle Cloud, GitHub)", "Reference download", "None", "Nothing (plain downloads)", "On", "EXP-001 skips CDN edges; findings name the hosting provider"},
	{"RDAP (rdap.org)", "Registration data", "None", "The domain name", "On", "DNS-006"},
	{"crt.sh brand watch", "Look-alikes: certificates for new domains containing a brand word", "None", "The brand words (each domain's own name, plus any configured)", "On when the look-alike check is on", "BRAND-001, BRAND-005"},
	{"Newly registered domains feed", "Look-alikes: a daily list of new domains", "Your own licensed feed (optional key)", "Nothing (the list is downloaded and matched locally)", "Off until an address is saved", "BRAND-001, BRAND-005"},
	{"Shodan InternetDB", "Exposure intelligence", "None", "IP addresses", "On", "EXP-001...004"},
	{"Shodan API", "Exposure intelligence", "Shodan key", "IP addresses", "Off until a key is saved", "EXP-001...004"},
	{"Censys", "Exposure intelligence", "Personal access token", "IP addresses", "Off until a token is saved", "EXP-001 (an independent second source)"},
	{"SANS Internet Storm Center", "Reputation of your own addresses (attack reports)", "None", "IP addresses", "On", "EXP-003 (an independent second source to Shodan's tags)"},
	{"Tor Project exit list", "Reputation of your own addresses (download)", "None", "Nothing (plain download)", "On", "EXP-005"},
	{"CISA Known Exploited Vulnerabilities", "Vulnerability intelligence (download)", "None", "Nothing (plain download)", "On", "EXP-002 severity and ordering"},
	{"FIRST EPSS", "Vulnerability intelligence", "None", "CVE identifiers", "On", "EXP-002 severity and ordering"},
	{"can-i-take-over-xyz fingerprints", "Takeover intelligence (download)", "None", "Nothing (plain download)", "On", "DNS-001, DNS-007"},
	{"Have I Been Pwned", "Leak monitoring", "Paid key, verified domain", "The domain name", "Off until a key is saved", "BRAND-002"},
	{"GitHub code search", "Leak monitoring", "Token", "The domain name", "Off until a token is saved", "BRAND-003"},
}
