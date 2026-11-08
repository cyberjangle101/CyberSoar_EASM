# Network connections and firewall rules

Every connection CyberSoar EASM accepts or opens, so you can write firewall and proxy rules for it. Everything here comes from the code; where a setting controls a connection, its name is given as it appears in **Settings** (and, in `code`, the form field behind it).

In short:

* **Inbound:** one TCP port for the web interface, the REST API and `/mcp`. Nothing else listens.
* **Outbound, always:** DNS to the configured resolvers (UDP and TCP 53), and HTTPS (TCP 443) to the intelligence sources that are on by default.
* **Outbound, only when you switch it on:** active checks of your own hosts (TCP and UDP to their ports), API-key services, email, alert channels, Active Directory and updates.

If you run on Kubernetes, see also [KUBERNETES.md](KUBERNETES.md#outbound-traffic-and-your-public-ip) for the NetworkPolicy and the egress IP.

## Inbound

| Port | Protocol | Who connects | Controlled by |
|---|---|---|---|
| `127.0.0.1:8080` by default | TCP, HTTPS (self-signed certificate made on first start) or plain HTTP | Browsers (the web interface), scripts using the REST API (`/api/v1/…`), AI assistants using `/mcp` | `listen` in the config file or `-listen`; otherwise **Settings → Web interface address**. HTTP instead of HTTPS: `plain_http: true` or `-plain-http`. MCP on or off: **Settings → AI assistants** (`mcp_enabled`, on by default; the port stays open either way) |

* The default address is loopback, so nothing on the network can reach it until you choose another address (for example `0.0.0.0:8443`). Then open that one port to the people and machines that need it, and only to them.
* The web interface, the API and MCP share that one port; there is no separate admin or metrics port.
* Behind a reverse proxy or a Kubernetes ingress, only the proxy needs to reach the port (`secure_cookies: true` when the proxy ends TLS).
* Browser-based assistants (claude.ai, chatgpt.com) would have to reach the agent from the internet. See [MCP.md](MCP.md#things-to-know-before-you-turn-it-on).

## DNS

| Destination | Protocol and port | What for | When | Controlled by |
|---|---|---|---|---|
| The configured resolvers, by default `1.1.1.1` and `8.8.8.8` | UDP 53, and TCP 53 when an answer is truncated | All scan lookups: your names and records, CNAME targets, look-alike domains, Team Cymru ASN lookups (TXT records under `origin.asn.cymru.com`), and spam blocklists (`bl.spamcop.net`, `psbl.surriel.com`) | Always | **Settings → DNS and ownership lookups → DNS resolvers** (`dns_resolvers`; IP addresses, optionally with `:port`) |
| `dns.google`, `cloudflare-dns.com` | HTTPS, TCP 443 (DNS-over-HTTPS, `POST /dns-query`) | The same question, asked again when a resolver cannot be reached (often: outbound port 53 is blocked) | On by default; used only when a resolver fails | **Fall back to DNS-over-HTTPS** (`dns_over_https`) |
| The operating system's own resolver | Whatever the OS uses | Looking up the host names of the services below (crt.sh, the SMTP server, webhook hosts, domain controllers…) | Always | The OS network settings (in Kubernetes, the cluster DNS) |

* Let the agent reach the resolvers on **both UDP and TCP 53**. Large answers (TXT, DNSSEC) come back truncated over UDP and are then asked again over TCP.
* To keep DNS inside your network, list your own recursive resolvers instead. They must resolve public names and answer TXT queries for `asn.cymru.com`.
* The ASN lookup does **not** use WHOIS on port 43: Team Cymru is asked over DNS through the resolvers above. Its fallback, RIPEstat, is HTTPS (next section).

## Intelligence sources (HTTPS, TCP 443)

These are web APIs and downloads. All are HTTPS on port 443 and all can go through an HTTP(S) proxy (see [Proxies](#proxies)). The default column is the factory setting.

**Subdomain discovery** (Settings → Data sources):

| Host | What for | Default | Controlled by |
|---|---|---|---|
| `crt.sh` | Certificate Transparency search | On | `crtsh_enabled` |
| `api.certspotter.com` | Second Certificate Transparency search | On | `certspotter_enabled` |
| `api.hackertarget.com` | Host search; also reverse-IP lookups (Wider discovery) | Host search on; reverse IP off | `hackertarget_enabled`, `reverseip_enabled` |
| `urlscan.io` | Names seen in public scans | On | `urlscan_enabled` |
| `ip.thc.org` | Names from passive DNS, certificates and scans (`POST /api/v1/lookup/subdomains`, up to 10 pages two seconds apart) | On | `thc_enabled` |
| `web.archive.org` | Names in archived URLs | Off | `wayback_enabled` |
| `otx.alienvault.com` | Passive DNS | Off; needs a free key | `otx_enabled` + OTX API key |
| `jonlu.ca` | Anubis subdomain dataset | Off (the service blocks automated clients) | `anubis_enabled` |

**Ownership and exposure** (Settings → Exposure intelligence, and DNS and ownership lookups):

| Host | What for | Default | Controlled by |
|---|---|---|---|
| `stat.ripe.net` | ASN fallback when Team Cymru fails | On | `asn_bgpview_fallback` (and `asn_enabled`) |
| `internetdb.shodan.io` | Open ports, CVEs and tags per IP | On | `internetdb_enabled` |
| `rdap.org`, then the registry's own RDAP server it redirects to (for example `rdap.verisign.com` for `.com`) | Registrar and expiry date; whether a domain is registered | On | `rdap_enabled` |
| `isc.sans.edu` | SANS Internet Storm Center reports per IP | On | `isc_enabled` |
| `api.first.org` | EPSS scores (only CVE IDs are sent) | On | `epss_enabled` |
| `api.shodan.io` | Shodan host data; optional subdomain search | Off; needs a key | `shodan_enabled` + key; `shodan_domain_lookup` |
| `api.platform.censys.io` | Censys host data | Off; needs a token | `censys_enabled` + token |
| `www.virustotal.com` | Subdomains | Off; needs a key | `virustotal_enabled` + key |
| `api.github.com` | Code search for your domain | Off; needs a token | `github_enabled` + token (Threat intelligence) |
| `haveibeenpwned.com` | Breached accounts at your domain | Off; needs a paid key | `hibp_enabled` + key (Threat intelligence) |
| `registry.npmjs.org`, `pypi.org` | Dependency confusion: does each package name exist | Off; also needs active checks | `dependency_confusion` (Threat intelligence) |

**Downloaded feeds.** Nothing about your domains is sent; each file is fetched at most once per refresh period, at the start of a scan.

| Host | Feed | Refreshed | Controlled by |
|---|---|---|---|
| `www.cisa.gov` | Known Exploited Vulnerabilities | Daily | `kev_enabled` |
| `check.torproject.org` | Tor exit nodes | Every 6 hours | `tor_exit_enabled` |
| `raw.githubusercontent.com` | can-i-take-over-xyz takeover fingerprints | Weekly | `takeover_feed_enabled` |
| `ip-ranges.amazonaws.com`, `www.gstatic.com` | AWS and Google Cloud IP ranges | Daily | `cloud_ranges_enabled` |
| `api.cloudflare.com`, `api.fastly.com`, `docs.oracle.com`, `api.github.com` | Cloudflare, Fastly, Oracle Cloud and GitHub IP ranges | Weekly | `cloud_ranges_enabled` |

All of these are on by default.

**Links people click.** Finding and asset pages show evidence links to `www.shodan.io`, `search.censys.io`, `www.virustotal.com`, `nvd.nist.gov`, `crt.sh`, `www.ssllabs.com`, `rdap.org`, `urlscan.io`, `dns.google`, `mxtoolbox.com`, `securityheaders.com`, `github.com`, `haveibeenpwned.com`, `www.npmjs.com` and `pypi.org`. The agent never fetches these itself; the browser of whoever clicks does.

## Active checks of your hosts

Off by default (**Settings → Active checks → Run active checks during scans**, `active_checks`). When on, the agent connects straight to the addresses your DNS names resolve to. It does **not** port-scan: apart from 80 and 443 it only connects to ports that exposure data (InternetDB, Shodan, Censys) already reports open.

| Destination | Protocol and port | What for | Controlled by |
|---|---|---|---|
| Your hosts' addresses | TCP 80 (HTTP), TCP 443 (HTTPS) | Home page, TLS certificate, security headers, a few well-known files, `security.txt`, the certificate shown without SNI | `active_checks`; files: `active_paths` |
| Your hosts' addresses | TCP 3000, 5000, 8000, 8008, 8080, 8081, 8181, 8443, 8888, 9443, where exposure data reports them open | The same web checks on other web ports (HTTPS on 8443 and 9443, HTTP on the rest) | `active_checks` |
| Your hosts' addresses | TCP 21, 2375, 5000, 5601, 5984, 6379, 6443, 8123, 8500, 8983, 9090, 9200, 10250, 10255, 11211, 27017, where exposure data reports them open | Whether FTP, Docker, Docker registry, Kibana, CouchDB, Redis, Kubernetes, ClickHouse, Consul, Solr, Prometheus, Elasticsearch, kubelet, Memcached or MongoDB answer without a password | `active_services` |
| Your hosts' addresses | UDP 53, where exposure data reports 53 open | Open resolver test (one recursive question for `example.com`) | `active_services` |
| Your domain's own nameservers (those on your networks) | TCP 53 | Zone transfer (AXFR) test | `active_services` |
| Your web services found above | Their own TCP ports | Weak TLS ciphers, NTLM details, CDN origin bypass | `active_services` (origin bypass also needs `cloud_ranges_enabled`) |
| Your hosts' addresses | UDP 161 | SNMP with the default communities `public` and `private` | `active_snmp` (off by default, even with active checks on) |
| `*.s3.amazonaws.com`, `storage.googleapis.com`, `*.digitaloceanspaces.com`, `*.aliyuncs.com`, `*.blob.core.windows.net`, `firebasestorage.googleapis.com`, `*.firebaseio.com` | HTTPS, TCP 443 | Whether storage your DNS names or pages point to is public or missing | `active_buckets` |
| Look-alike domains someone else registered | TCP 443, then 80 | Home page and icon, compared with yours | `lookalike_probe` (also needs `lookalike_enabled`; both off by default) |

* Only public, routable addresses are probed; the agent refuses private, loopback, link-local and metadata addresses itself. When an entity has expected ASNs or organisation keywords, only addresses inside them are probed, unless **Also probe addresses outside my expected networks** (`active_foreign`) is on.
* The checks only read (GET requests, TLS handshakes and read-only protocol questions), but the targets' intrusion detection will still see them. **Give the agent a dedicated egress IP** and tell the owners of the targets about it, as [KUBERNETES.md](KUBERNETES.md#outbound-traffic-and-your-public-ip) describes; the same applies to a Windows or Linux server.
* Screenshots (`screenshots`, off by default) start a local Chrome, Chromium or Edge that loads each page from the same address and port as the probe.
* [RULES.md](RULES.md) lists every path, product and port each rule checks. The port lists there that classify exposure data (for example the risky-service ports) are matched against third-party data; the agent does not connect to them.

## Optional integrations

| Destination | Protocol and port | What for | Controlled by |
|---|---|---|---|
| Your SMTP server | TCP 587 (STARTTLS), 465 (implicit TLS) or 25 (no encryption); any port you set | Alert emails, the scheduled report, test emails | **Settings → Email (SMTP)**: `smtp_enabled`, `smtp_host`, `smtp_port`, `smtp_security` |
| The webhook, Slack or Microsoft Teams URL you enter | HTTPS (or HTTP), the URL's port, usually 443 | Alert channel messages | **Settings → Alert channels** |
| Your Jira site | HTTPS, usually 443 | Tickets for findings | **Settings → Alert channels** (Jira) |
| Your syslog / SIEM collector | UDP, TCP or TLS to the port you enter (514 is usual for UDP and TCP, 6514 for TLS) | Alert events as CEF or JSON | **Settings → Alert channels** (Syslog). Private or loopback addresses only |
| Your domain controllers | TCP 636 (LDAPS, the default) or 389 (StartTLS); any port you add to the server name | Active Directory sign-in | **Settings → Directory sign-in**. Unencrypted LDAP is not supported |
| `api.github.com`, then `github.com` and `*.githubusercontent.com` | HTTPS, TCP 443 | Daily check for a newer release; downloading and verifying an update when an administrator installs one | **Update check** in Settings → Organisation (`update_check`, on by default). Installing always needs an administrator (or `-update`) |

The API-key services (Shodan, Censys, VirusTotal, GitHub, Have I Been Pwned, OTX) are in the intelligence tables above.

## Proxies

The agent honours the standard `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` environment variables (Go's `http.ProxyFromEnvironment`). On Windows it does **not** read the system (Internet Options) proxy, so set the variables for the account or service that runs the agent.

These go through the proxy:

* every intelligence source, feed and the RIPEstat fallback;
* webhooks, Slack, Teams and Jira;
* the update check and downloads.

These never use a proxy and need a direct route (or a firewall rule):

* **DNS** to the resolvers (UDP and TCP 53), and the DNS-over-HTTPS fallback to `dns.google` and `cloudflare-dns.com` (TCP 443);
* **active checks**: every probe connects straight to the target's address, including the cloud storage checks;
* **SMTP, syslog and LDAP**;
* the **reachability test behind System health** (run after start-up, at intervals, and by *Check connections now*), which opens a TLS connection directly to each enabled discovery source and feed on port 443. Behind a proxy that is the only way out, those sources show as unreachable there even while scans reach them through the proxy;
* **screenshots**: the browser is only allowed to resolve the target's name, so a proxy given by host name will not work for it.
