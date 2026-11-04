package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
	utf16x "unicode/utf16"

	"github.com/miekg/dns"
)

// Network-service checks (EASM-EXP-006, -009, -010, EASM-DNS-010, -011, EASM-TLS-010).
// Each sends the smallest read-only request that proves the point, to ports that exposure
// data already reports open (SNMP aside, which has its own switch), and only through the
// prober's dialer, so the address policy applies to every connection.

// NetHit is one problem a network-service check found.
type NetHit struct {
	IP       string
	Port     int
	Kind     string // finding kind
	Severity string
	What     string
	Slug     string // distinguishes several findings of one kind on one address and port
}

func (p *Prober) conn(ctx context.Context, network, ip string, port int) (net.Conn, error) {
	c, err := p.dialer().DialContext(ctx, network, p.addr(ip, port))
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(p.cfg.Timeout))
	return c, nil
}

// exchangeLine sends one request and reads what comes back (up to 8 KiB).
func (p *Prober) exchangeLine(ctx context.Context, ip string, port int, req string) (string, error) {
	c, err := p.conn(ctx, "tcp", ip, port)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, req); err != nil {
		return "", err
	}
	buf := make([]byte, 8192)
	n, err := io.ReadAtLeast(c, buf, 1)
	if n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}

// ---- EASM-EXP-006: datastores and control APIs that answer without a password

// datastoreChecks maps a port to the check for the service usually found there.
var datastoreChecks = map[int]struct {
	Name  string
	Check func(p *Prober, ctx context.Context, ip string, port int) (what string, err error)
}{
	6379:  {"Redis", (*Prober).redisOpen},
	11211: {"Memcached", (*Prober).memcachedOpen},
	9200:  {"Elasticsearch", (*Prober).elasticOpen},
	27017: {"MongoDB", (*Prober).mongoOpen},
	2375:  {"Docker API", (*Prober).dockerOpen},
	10250: {"Kubernetes kubelet", (*Prober).kubeletOpen},
	10255: {"Kubernetes kubelet (read-only port)", (*Prober).kubeletOpen},
	21:    {"FTP", (*Prober).ftpAnonymous},
	// Control and data APIs that are meant to sit behind authentication (added in 1.9.18).
	6443: {"Kubernetes API server", (*Prober).kubeAPIOpen},
	5000: {"Docker registry", (*Prober).registryOpen},
	8500: {"Consul", (*Prober).consulOpen},
	5984: {"CouchDB", (*Prober).couchOpen},
	8983: {"Apache Solr", (*Prober).solrOpen},
	8123: {"ClickHouse", (*Prober).clickhouseOpen},
	5601: {"Kibana", (*Prober).kibanaOpen},
	9090: {"Prometheus", (*Prober).prometheusOpen},
}

// datastoreSeverity lowers the rating for services that expose metadata rather than data (default High).
var datastoreSeverity = map[int]string{9090: "medium"}

// okJSON fetches path and reports whether it answered 200 with every marker in its body.
func (p *Prober) okJSON(ctx context.Context, scheme, ip string, port int, path string, markers ...string) (*fetched, bool, error) {
	r, err := p.httpJSON(ctx, scheme, ip, port, path)
	if err != nil {
		return nil, false, err
	}
	if r.Status != http.StatusOK {
		return r, false, nil
	}
	for _, m := range markers {
		if !bytes.Contains(r.Body, []byte(m)) {
			return r, false, nil
		}
	}
	return r, true, nil
}

func (p *Prober) kubeAPIOpen(ctx context.Context, ip string, port int) (string, error) {
	if _, ok, err := p.okJSON(ctx, "https", ip, port, "/api/v1/namespaces", `"NamespaceList"`); err != nil || !ok {
		return "", err
	}
	return "the Kubernetes API server lists its namespaces to anonymous users, so anyone can read (and possibly change) the cluster", nil
}

func (p *Prober) registryOpen(ctx context.Context, ip string, port int) (string, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		r, ok, err := p.okJSON(ctx, scheme, ip, port, "/v2/_catalog?n=100", `"repositories"`)
		if err != nil {
			lastErr = err
			continue
		}
		if ok {
			var cat struct{ Repositories []string }
			_ = json.Unmarshal(r.Body, &cat)
			return fmt.Sprintf("the Docker registry lists its images without signing in (%d listed), so anyone can download them, and the secrets and code built into them", len(cat.Repositories)), nil
		}
		return "", nil
	}
	return "", lastErr
}

func (p *Prober) consulOpen(ctx context.Context, ip string, port int) (string, error) {
	if _, ok, err := p.okJSON(ctx, "http", ip, port, "/v1/agent/self", `"Config"`, `"Datacenter"`); err != nil || !ok {
		return "", err
	}
	return "the Consul agent API answers without a token, which exposes the service catalogue and key-value store and can allow running commands", nil
}

func (p *Prober) couchOpen(ctx context.Context, ip string, port int) (string, error) {
	if _, ok, err := p.okJSON(ctx, "http", ip, port, "/", `"couchdb"`); err != nil || !ok {
		return "", err
	}
	r, ok, err := p.okJSON(ctx, "http", ip, port, "/_all_dbs")
	if err != nil || !ok || !bytes.HasPrefix(bytes.TrimSpace(r.Body), []byte("[")) {
		return "", err
	}
	var dbs []string
	_ = json.Unmarshal(r.Body, &dbs)
	return fmt.Sprintf("CouchDB lists its databases without a password (%d listed), so anyone can read and change them", len(dbs)), nil
}

func (p *Prober) solrOpen(ctx context.Context, ip string, port int) (string, error) {
	if _, ok, err := p.okJSON(ctx, "http", ip, port, "/solr/admin/cores?action=STATUS&wt=json", `"responseHeader"`, `"status"`); err != nil || !ok {
		return "", err
	}
	return "the Apache Solr admin API answers without a password, so anyone can search, change or delete its indexes", nil
}

func (p *Prober) clickhouseOpen(ctx context.Context, ip string, port int) (string, error) {
	r, err := p.httpJSON(ctx, "http", ip, port, "/?query=SELECT%20version()")
	if err != nil {
		return "", err
	}
	if r.Status == http.StatusOK && r.Header.Get("X-ClickHouse-Summary") != "" {
		return "ClickHouse " + truncate(strings.TrimSpace(string(r.Body)), 30) + " runs queries without a password (its default user has none), so anyone can read and change its data", nil
	}
	return "", nil
}

func (p *Prober) kibanaOpen(ctx context.Context, ip string, port int) (string, error) {
	if _, ok, err := p.okJSON(ctx, "http", ip, port, "/api/status", `"version"`, `"status"`); err != nil || !ok {
		return "", err
	}
	return "Kibana answers without signing in, so anyone can search the Elasticsearch data behind it", nil
}

func (p *Prober) prometheusOpen(ctx context.Context, ip string, port int) (string, error) {
	if _, ok, err := p.okJSON(ctx, "http", ip, port, "/api/v1/status/config", `"status":"success"`, `"yaml"`); err != nil || !ok {
		return "", err
	}
	return "Prometheus shows its configuration and metrics without signing in, which maps the internal systems it monitors", nil
}

func (p *Prober) redisOpen(ctx context.Context, ip string, port int) (string, error) {
	r, err := p.exchangeLine(ctx, ip, port, "INFO server\r\n")
	if err != nil {
		return "", err
	}
	if i := strings.Index(r, "redis_version:"); i >= 0 {
		v := strings.TrimSpace(strings.SplitN(r[i+len("redis_version:"):], "\n", 2)[0])
		return "Redis " + v + " answers INFO without a password, so anyone can read and change its data", nil
	}
	return "", nil
}

func (p *Prober) memcachedOpen(ctx context.Context, ip string, port int) (string, error) {
	r, err := p.exchangeLine(ctx, ip, port, "stats\r\n")
	if err != nil {
		return "", err
	}
	if strings.Contains(r, "STAT version") {
		return "Memcached answers stats without a password, so anyone can read cached data (and use it for traffic amplification)", nil
	}
	return "", nil
}

func (p *Prober) httpJSON(ctx context.Context, scheme, ip string, port int, path string) (*fetched, error) {
	return p.fetch(ctx, scheme, ip, ip, port, path)
}

func (p *Prober) elasticOpen(ctx context.Context, ip string, port int) (string, error) {
	r, err := p.httpJSON(ctx, "http", ip, port, "/")
	if err != nil {
		return "", err
	}
	if r.Status != http.StatusOK || !bytes.Contains(r.Body, []byte(`"cluster_name"`)) {
		return "", nil
	}
	n := 0
	if ix, err := p.httpJSON(ctx, "http", ip, port, "/_cat/indices?h=index"); err == nil && ix.Status == http.StatusOK {
		n = len(strings.Fields(string(ix.Body)))
	}
	return fmt.Sprintf("Elasticsearch answers without a password (%d indices listed), so anyone can read, change or delete the data", n), nil
}

func (p *Prober) dockerOpen(ctx context.Context, ip string, port int) (string, error) {
	r, err := p.httpJSON(ctx, "http", ip, port, "/version")
	if err != nil {
		return "", err
	}
	var v struct{ Version, ApiVersion string }
	if r.Status == http.StatusOK && json.Unmarshal(r.Body, &v) == nil && v.ApiVersion != "" {
		return "the Docker API " + v.Version + " answers without authentication, which gives anyone full control of the host", nil
	}
	return "", nil
}

func (p *Prober) kubeletOpen(ctx context.Context, ip string, port int) (string, error) {
	scheme := "https"
	if port == 10255 {
		scheme = "http"
	}
	r, err := p.httpJSON(ctx, scheme, ip, port, "/pods")
	if err != nil {
		return "", err
	}
	if r.Status == http.StatusOK && bytes.Contains(r.Body, []byte(`"PodList"`)) {
		return "the Kubernetes kubelet lists its pods without authentication; on the main port that usually also allows running commands in them", nil
	}
	return "", nil
}

func (p *Prober) ftpAnonymous(ctx context.Context, ip string, port int) (string, error) {
	c, err := p.conn(ctx, "tcp", ip, port)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	rd := bufio.NewReader(c)
	reply := func() string {
		var last string
		for i := 0; i < 20; i++ { // multi-line replies end with "NNN " (a space after the code)
			line, err := rd.ReadString('\n')
			if err != nil {
				return last
			}
			last = line
			if len(line) >= 4 && line[3] == ' ' {
				return line
			}
		}
		return last
	}
	if !strings.HasPrefix(reply(), "220") {
		return "", nil
	}
	_, _ = io.WriteString(c, "USER anonymous\r\n")
	if r := reply(); strings.HasPrefix(r, "230") {
		_, _ = io.WriteString(c, "QUIT\r\n")
		return "the FTP server accepts anonymous sign-in, so anyone can list (and possibly upload) files", nil
	} else if !strings.HasPrefix(r, "331") {
		return "", nil
	}
	_, _ = io.WriteString(c, "PASS easm-check@example.invalid\r\n")
	r := reply()
	_, _ = io.WriteString(c, "QUIT\r\n")
	if strings.HasPrefix(r, "230") {
		return "the FTP server accepts anonymous sign-in, so anyone can list (and possibly upload) files", nil
	}
	return "", nil
}

// mongoOpen sends one OP_MSG asking for the list of databases (names only).
func (p *Prober) mongoOpen(ctx context.Context, ip string, port int) (string, error) {
	c, err := p.conn(ctx, "tcp", ip, port)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	doc := bsonDoc(bsonInt32("listDatabases", 1), bsonBool("nameOnly", true), bsonString("$db", "admin"))
	body := append([]byte{0, 0, 0, 0, 0}, doc...) // flagBits, then section kind 0 (body)
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:], uint32(16+len(body)))
	binary.LittleEndian.PutUint32(hdr[4:], 1)
	binary.LittleEndian.PutUint32(hdr[12:], 2013) // OP_MSG
	if _, err := c.Write(append(hdr, body...)); err != nil {
		return "", err
	}
	resp := make([]byte, 65536)
	n, _ := io.ReadAtLeast(c, resp, 16)
	if n < 21 {
		return "", nil
	}
	r := resp[:n]
	// An open server answers ok: 1 with a "databases" array; a protected one answers ok: 0 (Unauthorized).
	if bytes.Contains(r, []byte("databases\x00")) && !bytes.Contains(r, []byte("errmsg")) {
		return "MongoDB lists its databases without a password, so anyone can read and change the data", nil
	}
	return "", nil
}

func bsonDoc(elems ...[]byte) []byte {
	var b []byte
	for _, e := range elems {
		b = append(b, e...)
	}
	out := make([]byte, 4, 5+len(b))
	binary.LittleEndian.PutUint32(out, uint32(5+len(b)))
	return append(append(out, b...), 0)
}
func bsonInt32(k string, v int32) []byte {
	b := append([]byte{0x10}, append([]byte(k), 0)...)
	return binary.LittleEndian.AppendUint32(b, uint32(v))
}
func bsonBool(k string, v bool) []byte {
	b := append([]byte{0x08}, append([]byte(k), 0)...)
	if v {
		return append(b, 1)
	}
	return append(b, 0)
}
func bsonString(k, v string) []byte {
	b := append([]byte{0x02}, append([]byte(k), 0)...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(v)+1))
	return append(append(b, v...), 0)
}

// ---- EASM-DNS-010 and -011: zone transfer and open resolver

// zoneTransfer asks a nameserver for a full copy of the zone (AXFR) and returns how many records it sent.
func (p *Prober) zoneTransfer(ctx context.Context, ip, zone string) (int, error) {
	c, err := p.conn(ctx, "tcp", ip, 53)
	if err != nil {
		return 0, err
	}
	t := &dns.Transfer{Conn: &dns.Conn{Conn: c}, DialTimeout: p.cfg.Timeout, ReadTimeout: p.cfg.Timeout}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	env, err := t.In(m, "")
	if err != nil {
		return 0, err
	}
	n := 0
	for e := range env {
		if e.Error != nil {
			return n, e.Error
		}
		n += len(e.RR)
		if n > 5000 {
			break // enough to prove it
		}
	}
	return n, nil
}

// openResolver asks an address to resolve a name it is not responsible for.
func (p *Prober) openResolver(ctx context.Context, ip string) (bool, error) {
	c, err := p.conn(ctx, "udp", ip, 53)
	if err != nil {
		return false, err
	}
	defer func() { _ = c.Close() }()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.RecursionDesired = true
	co := &dns.Conn{Conn: c}
	if err := co.WriteMsg(m); err != nil {
		return false, err
	}
	in, err := co.ReadMsg()
	if err != nil {
		return false, err
	}
	return in.RecursionAvailable && in.Rcode == dns.RcodeSuccess && len(in.Answer) > 0 && !in.Authoritative, nil
}

// ---- EASM-EXP-009: SNMP default communities

// snmpGetSysDescr builds an SNMPv2c GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0).
func snmpGetSysDescr(community string) []byte {
	tlv := func(tag byte, v []byte) []byte {
		if len(v) < 128 {
			return append([]byte{tag, byte(len(v))}, v...)
		}
		return append([]byte{tag, 0x81, byte(len(v))}, v...)
	}
	oid := []byte{0x2b, 6, 1, 2, 1, 1, 1, 0}
	varbind := tlv(0x30, append(tlv(0x06, oid), 0x05, 0x00))
	pdu := tlv(0xa0, append(append(append(tlv(0x02, []byte{0x01}), tlv(0x02, []byte{0})...), tlv(0x02, []byte{0})...), tlv(0x30, varbind)...))
	return tlv(0x30, append(append(tlv(0x02, []byte{1}), tlv(0x04, []byte(community))...), pdu...))
}

// snmpDefault tries the communities public and private; it returns the one accepted and the device description.
func (p *Prober) snmpDefault(ctx context.Context, ip string) (community, descr string, err error) {
	for _, comm := range []string{"public", "private"} {
		c, err := p.conn(ctx, "udp", ip, 161)
		if err != nil {
			return "", "", err
		}
		_, _ = c.Write(snmpGetSysDescr(comm))
		buf := make([]byte, 2048)
		n, rerr := c.Read(buf)
		_ = c.Close()
		if rerr != nil || n == 0 {
			continue
		}
		// A reply carries a GetResponse (0xa2) whose value is an OCTET STRING after the OID.
		r := buf[:n]
		if i := bytes.Index(r, []byte{0x2b, 6, 1, 2, 1, 1, 1, 0}); i >= 0 && bytes.Contains(r, []byte{0xa2}) {
			v := r[i+8:]
			if len(v) > 2 && v[0] == 0x04 {
				l, off := int(v[1]), 2
				if v[1] == 0x81 && len(v) > 3 {
					l, off = int(v[2]), 3
				}
				if off+l <= len(v) {
					return comm, strings.TrimSpace(string(v[off : off+l])), nil
				}
			}
			return comm, "", nil
		}
	}
	return "", "", nil
}

// ---- EASM-EXP-010: what an NTLM challenge reveals

// ntlmNegotiate is a standard NTLMSSP NEGOTIATE message asking for the target information.
var ntlmNegotiate, _ = base64.StdEncoding.DecodeString("TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")

// NTLMInfo is what a server's NTLM challenge says about it.
type NTLMInfo struct {
	NetBIOSDomain, NetBIOSComputer, DNSDomain, DNSComputer, Forest, OS string
}

func (n NTLMInfo) String() string {
	var parts []string
	for _, kv := range [][2]string{{"Active Directory domain", n.DNSDomain}, {"NetBIOS domain", n.NetBIOSDomain}, {"computer", n.DNSComputer},
		{"NetBIOS name", n.NetBIOSComputer}, {"forest", n.Forest}, {"Windows build", n.OS}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+" "+kv[1])
		}
	}
	return strings.Join(parts, ", ")
}

// parseNTLMChallenge reads the target information from an NTLMSSP CHALLENGE message.
func parseNTLMChallenge(b []byte) (NTLMInfo, bool) {
	var in NTLMInfo
	if len(b) < 48 || !bytes.HasPrefix(b, []byte("NTLMSSP\x00")) || binary.LittleEndian.Uint32(b[8:]) != 2 {
		return in, false
	}
	flags := binary.LittleEndian.Uint32(b[20:])
	tl, to := int(binary.LittleEndian.Uint16(b[40:])), int(binary.LittleEndian.Uint32(b[44:]))
	if flags&0x02000000 != 0 && len(b) >= 56 { // NEGOTIATE_VERSION
		in.OS = fmt.Sprintf("%d.%d.%d", b[48], b[49], binary.LittleEndian.Uint16(b[50:]))
	}
	if to+tl > len(b) || to < 0 {
		return in, in.OS != ""
	}
	av := b[to : to+tl]
	for len(av) >= 4 {
		id, l := binary.LittleEndian.Uint16(av), int(binary.LittleEndian.Uint16(av[2:]))
		if id == 0 || 4+l > len(av) {
			break
		}
		v := utf16le(av[4 : 4+l])
		switch id {
		case 1:
			in.NetBIOSComputer = v
		case 2:
			in.NetBIOSDomain = v
		case 3:
			in.DNSComputer = v
		case 4:
			in.DNSDomain = v
		case 5:
			in.Forest = v
		}
		av = av[4+l:]
	}
	return in, true
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16x.Decode(u))
}

// ntlmPaths are where Microsoft servers commonly accept NTLM sign-in.
var ntlmPaths = []string{"/", "/owa/", "/ews/exchange.asmx", "/autodiscover/autodiscover.xml", "/Microsoft-Server-ActiveSync", "/rpc/", "/mapi/", "/adfs/ls/", "/certsrv/"}

// ntlmInfo offers NTLM sign-in on a web service and reads the server's challenge.
func (p *Prober) ntlmInfo(ctx context.Context, wr *WebResult) (NTLMInfo, string, bool) {
	paths := ntlmPaths[:1]
	if microsoftHint(wr) {
		paths = ntlmPaths
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		r, err := p.fetchWith(ctx, http.MethodGet, wr.Scheme, wr.Host, wr.IP, wr.Port, path,
			map[string]string{"Authorization": "NTLM " + base64.StdEncoding.EncodeToString(ntlmNegotiate)}, nil)
		if err != nil || r.Status != http.StatusUnauthorized {
			continue
		}
		for _, h := range r.Header.Values("WWW-Authenticate") {
			for _, scheme := range []string{"NTLM ", "Negotiate "} {
				if strings.HasPrefix(h, scheme) {
					raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(scheme):]))
					if err != nil {
						continue
					}
					if in, ok := parseNTLMChallenge(raw); ok {
						return in, path, true
					}
				}
			}
		}
	}
	return NTLMInfo{}, "", false
}

func microsoftHint(wr *WebResult) bool {
	first := strings.SplitN(wr.Host, ".", 2)[0]
	for _, w := range []string{"mail", "owa", "autodiscover", "exchange", "remote", "adfs", "sts", "sharepoint", "webmail"} {
		if first == w {
			return true
		}
	}
	for _, ph := range wr.Portals {
		for _, w := range []string{"Outlook", "Exchange", "AD FS", "RD Web", "SharePoint"} {
			if strings.Contains(ph.Name, w) {
				return true
			}
		}
	}
	return strings.Contains(wr.Server, "IIS")
}

// ---- EASM-TLS-010: weak cipher suites

// weakSuites are the suites a modern server must never agree to.
var weakSuites = map[uint16]string{
	0x0001: "NULL (RSA_WITH_NULL_MD5)", 0x0002: "NULL (RSA_WITH_NULL_SHA)", 0x003B: "NULL (RSA_WITH_NULL_SHA256)",
	0xC006: "NULL (ECDHE_ECDSA_WITH_NULL_SHA)", 0xC010: "NULL (ECDHE_RSA_WITH_NULL_SHA)",
	0x0003: "export (RSA_EXPORT_WITH_RC4_40_MD5)", 0x0006: "export (RSA_EXPORT_WITH_RC2_CBC_40_MD5)",
	0x0008: "export (RSA_EXPORT_WITH_DES40_CBC_SHA)", 0x0014: "export (DHE_RSA_EXPORT_WITH_DES40_CBC_SHA)",
	0x0004: "RC4 (RSA_WITH_RC4_128_MD5)", 0x0005: "RC4 (RSA_WITH_RC4_128_SHA)", 0xC007: "RC4 (ECDHE_ECDSA_WITH_RC4_128_SHA)",
	0xC011: "RC4 (ECDHE_RSA_WITH_RC4_128_SHA)", 0x0009: "DES (RSA_WITH_DES_CBC_SHA)",
	0x000A: "3DES (RSA_WITH_3DES_EDE_CBC_SHA)", 0x0016: "3DES (DHE_RSA_WITH_3DES_EDE_CBC_SHA)",
	0xC008: "3DES (ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)", 0xC012: "3DES (ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)",
	0x0018: "anonymous (DH_anon_WITH_RC4_128_MD5)", 0x001B: "anonymous (DH_anon_WITH_3DES_EDE_CBC_SHA)",
	0x0034: "anonymous (DH_anon_WITH_AES_128_CBC_SHA)", 0x003A: "anonymous (DH_anon_WITH_AES_256_CBC_SHA)",
	0xC018: "anonymous (ECDH_anon_WITH_AES_128_CBC_SHA)",
}

func sortedUint16Keys[V any](m map[uint16]V) []uint16 {
	out := make([]uint16, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// clientHello builds a TLS 1.2 ClientHello that offers only the given suites.
func clientHello(host string, suites []uint16) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)
	body = append(body, rnd...)
	body = append(body, 0) // no session id
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(suites)))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // null compression
	var ext []byte
	addExt := func(typ uint16, data []byte) {
		ext = binary.BigEndian.AppendUint16(ext, typ)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(data)))
		ext = append(ext, data...)
	}
	if host != "" && net.ParseIP(host) == nil {
		sni := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(host)))...)
		sni = append(sni, host...)
		addExt(0x0000, append(binary.BigEndian.AppendUint16(nil, uint16(len(sni))), sni...))
	}
	addExt(0x000a, []byte{0, 4, 0, 0x17, 0, 0x18})                               // supported_groups: P-256, P-384
	addExt(0x000b, []byte{1, 0})                                                 // ec_point_formats: uncompressed
	addExt(0x000d, []byte{0, 8, 0x04, 0x01, 0x02, 0x01, 0x04, 0x03, 0x02, 0x03}) // signature_algorithms
	addExt(0xff01, []byte{0})                                                    // renegotiation_info
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// chosenSuite sends a ClientHello and returns the suite the server picked (0 = refused).
func (p *Prober) chosenSuite(ctx context.Context, host, ip string, port int, suites []uint16) (uint16, error) {
	c, err := p.conn(ctx, "tcp", ip, port)
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(clientHello(host, suites)); err != nil {
		return 0, err
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return 0, nil // closed without a hello: refused
	}
	if hdr[0] != 0x16 {
		return 0, nil // an alert
	}
	rec := make([]byte, int(binary.BigEndian.Uint16(hdr[3:])))
	if _, err := io.ReadFull(c, rec); err != nil || len(rec) < 39 || rec[0] != 0x02 {
		return 0, nil
	}
	sid := int(rec[38])
	if len(rec) < 41+sid {
		return 0, nil
	}
	return binary.BigEndian.Uint16(rec[39+sid:]), nil
}

// weakCiphers lists the weak suites a TLS service agrees to (at most four, one handshake each).
func (p *Prober) weakCiphers(ctx context.Context, host, ip string, port int) ([]string, error) {
	offer := sortedUint16Keys(weakSuites)
	var found []string
	for i := 0; i < 4 && len(offer) > 0 && ctx.Err() == nil; i++ {
		s, err := p.chosenSuite(ctx, host, ip, port, offer)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			break
		}
		name, weak := weakSuites[s]
		if !weak {
			break
		}
		found = append(found, name)
		for j, o := range offer {
			if o == s {
				offer = append(offer[:j], offer[j+1:]...)
				break
			}
		}
	}
	return found, nil
}
