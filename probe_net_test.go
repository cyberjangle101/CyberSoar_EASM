package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
	utf16x "unicode/utf16"

	"github.com/miekg/dns"
)

// tcpService answers every connection with handle, and routes ip:port to it.
func (l *webLab) tcpService(ip string, port int, handle func(c net.Conn)) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handle(c)
			}()
		}
	}()
	l.routes[fmt.Sprintf("%s:%d", ip, port)] = ln.Addr().String()
}

// udpService answers every datagram with reply(request), and routes ip:port to it.
func (l *webLab) udpService(ip string, port int, reply func([]byte) []byte) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := reply(append([]byte(nil), buf[:n]...)); r != nil {
				_, _ = pc.WriteTo(r, from)
			}
		}
	}()
	l.routes[fmt.Sprintf("%s:%d", ip, port)] = pc.LocalAddr().String()
}

func utf16Bytes(s string) []byte {
	var b []byte
	for _, u := range utf16x.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// ntlmChallengeFor builds an NTLMSSP CHALLENGE naming a domain and computer, with a Windows version.
func ntlmChallengeFor(nbDomain, nbComputer, dnsDomain, dnsComputer string, build uint16) []byte {
	var info []byte
	for _, av := range []struct {
		id uint16
		v  string
	}{{2, nbDomain}, {1, nbComputer}, {4, dnsDomain}, {3, dnsComputer}} {
		v := utf16Bytes(av.v)
		info = binary.LittleEndian.AppendUint16(info, av.id)
		info = binary.LittleEndian.AppendUint16(info, uint16(len(v)))
		info = append(info, v...)
	}
	info = append(info, 0, 0, 0, 0)
	b := []byte("NTLMSSP\x00")
	b = binary.LittleEndian.AppendUint32(b, 2)
	b = append(b, 0, 0, 0, 0, 56, 0, 0, 0) // empty target name
	b = binary.LittleEndian.AppendUint32(b, 0x02000000|0x00800000|0x00000001)
	b = append(b, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(info)))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(info)))
	b = binary.LittleEndian.AppendUint32(b, 56)
	b = append(b, 10, 0)
	b = binary.LittleEndian.AppendUint16(b, build)
	b = append(b, 0, 0, 0, 15)
	return append(b, info...)
}

func TestNetworkServiceChecks(t *testing.T) {
	l := newWebLab(t)
	h, d := l.h, l.h.dns
	st, _ := h.store.LoadSettings()
	st.InternetDBEnabled, st.ActiveServices, st.ActiveSNMP, st.CloudRangesEnabled = true, true, true, true
	st.ActiveTimeoutSeconds = 2 // SNMP waits this long at each address without a device
	h.saveSettings(st)
	l.setProber()
	owned := func(name, ip string, ports ...int) {
		l.host(name, ip)
		if len(ports) > 0 {
			h.intel.idb[ip] = idbBody(ip, ports, nil, nil)
		}
	}

	// data: Redis, Elasticsearch, MongoDB, Docker and anonymous FTP, all reported open by exposure data
	owned("data.example.test", "203.0.113.70", 21, 2375, 6379, 9200, 27017)
	l.tcpService("203.0.113.70", 6379, func(c net.Conn) {
		_, _ = bufio.NewReader(c).ReadString('\n')
		_, _ = fmt.Fprint(c, "$120\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n")
	})
	l.serve("203.0.113.70", 9200, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_cat/indices") {
			_, _ = fmt.Fprint(w, "customers\norders\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"cluster_name":"prod","tagline":"You Know, for Search"}`)
	}), nil, 0)
	l.serve("203.0.113.70", 2375, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"Version":"24.0.7","ApiVersion":"1.43"}`)
	}), nil, 0)
	l.tcpService("203.0.113.70", 27017, func(c net.Conn) {
		buf := make([]byte, 1024)
		_, _ = c.Read(buf)
		reply := append(make([]byte, 21), []byte("\x04databases\x00\x05totalSize\x00\x01ok\x00")...)
		_, _ = c.Write(reply)
	})
	l.tcpService("203.0.113.70", 21, func(c net.Conn) {
		rd := bufio.NewReader(c)
		_, _ = fmt.Fprint(c, "220 FTP ready\r\n")
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "USER"):
				_, _ = fmt.Fprint(c, "331 Password please\r\n")
			case strings.HasPrefix(line, "PASS"):
				_, _ = fmt.Fprint(c, "230 Welcome\r\n")
			default:
				_, _ = fmt.Fprint(c, "221 Bye\r\n")
				return
			}
		}
	})
	// The same address answers SNMP with the default community.
	l.udpService("203.0.113.70", 161, func(req []byte) []byte {
		if !strings.Contains(string(req), "public") {
			return nil
		}
		descr := "Cisco IOS Software, C2960"
		r := []byte{0x30, 0x00, 0xa2, 0x00, 0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 1, 0, 0x04, byte(len(descr))}
		return append(r, descr...)
	})

	// The domain's nameserver hands out the zone.
	d.add(t, "example.test. 60 IN NS ns1.example.test.")
	owned("ns1.example.test", "203.0.113.53")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	axfr := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 || r.Question[0].Qtype != dns.TypeAXFR {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		soa, _ := dns.NewRR("example.test. 60 IN SOA ns1.example.test. admin.example.test. 1 7200 900 1209600 60")
		a1, _ := dns.NewRR("secret-admin.example.test. 60 IN A 10.1.2.3")
		a2, _ := dns.NewRR("vpn.example.test. 60 IN A 203.0.113.99")
		ch := make(chan *dns.Envelope, 1)
		tr := new(dns.Transfer)
		go func() { ch <- &dns.Envelope{RR: []dns.RR{soa, a1, a2, soa}}; close(ch) }()
		_ = tr.Out(w, r, ch)
		w.Hijack()
	})}
	go func() { _ = axfr.ActivateAndServe() }()
	t.Cleanup(func() { _ = axfr.Shutdown() })
	l.routes["203.0.113.53:53"] = ln.Addr().String()

	// An open resolver.
	owned("dns.example.test", "203.0.113.54", 53)
	l.udpService("203.0.113.54", 53, func(req []byte) []byte {
		q := new(dns.Msg)
		if q.Unpack(req) != nil {
			return nil
		}
		m := new(dns.Msg)
		m.SetReply(q)
		m.RecursionAvailable = true
		a, _ := dns.NewRR("example.com. 60 IN A 93.184.215.14")
		m.Answer = append(m.Answer, a)
		b, _ := m.Pack()
		return b
	})

	// mail: NTLM sign-in reveals the Windows domain; it still agrees to RC4.
	owned("mail.example.test", "203.0.113.55")
	mailCert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "mail.example.test")
	srv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "NTLM ") {
			w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ntlmChallengeFor("CORP", "MAIL01", "corp.example.local", "mail01.corp.example.local", 20348)))
		} else {
			w.Header().Add("WWW-Authenticate", "NTLM")
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	l.serveCiphers("203.0.113.55", 443, srv, &mailCert, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}) // strong and weak, as such servers usually are

	// lb: an AWS load balancer with no healthy target; fn: a Lambda URL that returns data
	d.add(t, "lb.example.test. 60 IN CNAME prod-123.us-east-1.elb.amazonaws.com.")
	d.add(t, "prod-123.us-east-1.elb.amazonaws.com. 60 IN A 203.0.113.56")
	d.addIP(t, "203.0.113.56", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.src.addAnubis("lb.example.test")
	l.serve("203.0.113.56", 80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}), nil, 0)
	d.add(t, "fn.example.test. 60 IN CNAME abc123.lambda-url.us-east-1.on.aws.")
	d.add(t, "abc123.lambda-url.us-east-1.on.aws. 60 IN A 203.0.113.57")
	d.addIP(t, "203.0.113.57", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	h.src.addAnubis("fn.example.test")
	fnCert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "fn.example.test")
	l.serve("203.0.113.57", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"users":[{"id":1,"email":"a@example.test"}],"count":1}`)
	}), &fnCert, tls.VersionTLS12)

	// shop: behind a CDN, but the origin (one of our own addresses) serves it too
	shopPage := page("Acme Shop", "the shop")
	d.add(t, "shop.example.test. 60 IN A 198.51.100.200")
	h.src.addAnubis("shop.example.test")
	shopCert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "shop.example.test", "origin.example.test")
	l.serve("198.51.100.200", 443, shopPage, &shopCert, tls.VersionTLS12)
	owned("origin.example.test", "203.0.113.58")
	l.serve("203.0.113.58", 443, shopPage, &shopCert, tls.VersionTLS12)
	h.eng.feeds.mu.Lock()
	h.eng.feeds.ranges = map[string][]cloudNet{feedCloudflare: {{net: netip.MustParsePrefix("198.51.100.200/32"), CloudRange: CloudRange{Provider: "Cloudflare", CDN: true}}}}
	h.eng.feeds.mu.Unlock()

	tg := h.addTarget("example.test", "AS64500")
	h.scanN(tg.ID, 1)
	if tg2, _ := h.store.GetTarget(tg.ID); tg2.LastStatus != "ok" {
		t.Fatalf("scan: %s", tg2.LastError)
	}
	for _, w := range []struct{ kind, part, sev, text string }{
		{"unauthenticated-datastore", "Redis", "high", "Redis 7.2.4"},
		{"unauthenticated-datastore", "Elasticsearch", "high", "2 indices"},
		{"unauthenticated-datastore", "MongoDB", "high", "lists its databases"},
		{"unauthenticated-datastore", "Docker API", "high", "24.0.7"},
		{"unauthenticated-datastore", "FTP", "high", "anonymous"},
		{"dns-zone-transfer", "ns1.example.test", "high", "4 records"},
		{"dns-open-resolver", "dns.example.test", "medium", "example.com"},
		{"snmp-default-creds", "data.example.test", "high", "Cisco IOS"},
		{"ntlm-info-leak", "mail.example.test", "low", "corp.example.local"},
		{"tls-weak-cipher", "mail.example.test", "medium", "RC4"},
		{"orphaned-load-balancer", "lb.example.test", "medium", "HTTP 503"},
		{"exposed-function-url", "fn.example.test", "high", "AWS Lambda function URL"},
		{"waf-origin-bypass", "shop.example.test", "high", "203.0.113.58"},
	} {
		f := l.findingFor(w.kind, w.part)
		if f == nil {
			t.Errorf("missing %s for %s; open: %v", w.kind, w.part, l.openKinds())
			continue
		}
		if f.Severity != w.sev || !strings.Contains(f.Detail, w.text) {
			t.Errorf("%s for %s: severity %s, detail %q", w.kind, w.part, f.Severity, f.Detail)
		}
	}
	if f := l.findingFor("ntlm-info-leak", "20348"); f == nil {
		t.Error("Windows build not reported")
	}
	if f := l.findingFor("tls-weak-cipher", "fn.example.test"); f != nil {
		t.Errorf("a modern TLS server was reported: %s", f.Detail)
	}
}

// serveCiphers is serve with a fixed list of cipher suites and TLS 1.2 at most.
func (l *webLab) serveCiphers(ip string, port int, handler http.Handler, cert *tls.Certificate, suites []uint16) {
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, CipherSuites: suites, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12} //nolint:gosec // a deliberately weak test server
	srv.StartTLS()
	l.t.Cleanup(srv.Close)
	l.routes[fmt.Sprintf("%s:%d", ip, port)] = strings.TrimPrefix(srv.URL, "https://")
}

func TestNTLMChallengeParsing(t *testing.T) {
	in, ok := parseNTLMChallenge(ntlmChallengeFor("CORP", "MAIL01", "corp.example.local", "mail01.corp.example.local", 20348))
	if !ok || in.DNSDomain != "corp.example.local" || in.NetBIOSComputer != "MAIL01" || in.OS != "10.0.20348" {
		t.Fatalf("%+v", in)
	}
	if _, ok := parseNTLMChallenge([]byte("garbage")); ok {
		t.Error("garbage parsed")
	}
}

func TestSNMPRequestAndJSONShape(t *testing.T) {
	req := snmpGetSysDescr("public")
	if req[0] != 0x30 || !strings.Contains(string(req), "public") || !strings.Contains(string(req), "\x2b\x06\x01\x02\x01\x01\x01\x00") {
		t.Fatalf("bad SNMP request % x", req)
	}
	j := http.Header{"Content-Type": {"application/json"}}
	for body, want := range map[string]string{`{"message":"Forbidden"}`: "error", `{"a":1,"b":2}`: "data", `{"ok":true}`: "small", `[1,2]`: "data", `not json`: ""} {
		if got := jsonShape(j, []byte(body)); got != want {
			t.Errorf("jsonShape(%s) = %q, want %q", body, got, want)
		}
	}
	if jsonShape(http.Header{"Content-Type": {"text/html"}}, []byte(`{"a":1,"b":2}`)) != "" {
		t.Error("HTML treated as JSON")
	}
}
