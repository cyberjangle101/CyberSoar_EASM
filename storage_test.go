package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test tokens are put together at run time, so this file holds nothing a secret scanner (or a
// person) could mistake for a real key.
var (
	fakeStripe = "sk_" + "live_" + strings.Repeat("a1B2", 6)
	fakeAWS    = "AK" + "IA" + "QWERTYUIOPASDFGH"
	fakePub    = "pk_" + "live_" + strings.Repeat("c3D4", 6) // publishable: public by design, never reported
)

func TestPageStorageFindsLinkedBuckets(t *testing.T) {
	body := []byte(`<img src="https://Media-Bkt.s3.eu-west-1.amazonaws.com/a.png">
<script>fetch("https://s3.amazonaws.com/path-bkt/data.json")</script>
<link href="https://storage.googleapis.com/gcs-bkt/site.css">
<img src="https://spaces-bkt.ams3.cdn.digitaloceanspaces.com/x.png">
<img src="https://oss-bkt.oss-cn-hangzhou.aliyuncs.com/y.png">
<img src="https://acmestore.blob.core.windows.net/public/logo.png">
<script>const firebaseConfig = { databaseURL: "https://acme-app-default-rtdb.firebaseio.com", storageBucket: "acme-app.appspot.com" };</script>
<a href="https://example.com/s3.amazonaws.com">not a bucket</a>`)
	got := map[string]bool{}
	for _, r := range pageStorage(body, "https://www.example.test/") {
		got[r.Provider+"/"+r.Name] = true
		if r.Via != "https://www.example.test/" {
			t.Errorf("%s: via %q", r.Name, r.Via)
		}
	}
	for _, want := range []string{"s3/media-bkt", "s3/path-bkt", "gcs/gcs-bkt", "do/spaces-bkt.ams3", "oss/oss-bkt.oss-cn-hangzhou",
		"azure/acmestore/public", "firebase/acme-app-default-rtdb.firebaseio.com", "firebase-storage/acme-app.appspot.com"} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	if len(got) != 8 {
		t.Errorf("unexpected extra references: %v", got)
	}
}

func TestBucketsFromDNSCoverMoreProviders(t *testing.T) {
	got := map[string]bool{}
	for _, b := range bucketsFor("cdn.example.test", []string{"media.ams3.digitaloceanspaces.com.", "files.oss-eu-central-1.aliyuncs.com.", "assets.example.test.storage.googleapis.com."}) {
		got[b.Provider+"/"+b.Name] = true
	}
	for _, want := range []string{"do/media.ams3", "oss/files.oss-eu-central-1", "gcs/assets.example.test"} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
}

func TestClassifyStorageAnswers(t *testing.T) {
	cases := []struct {
		provider string
		status   int
		body     string
		public   bool
		missing  bool
		empty    bool
	}{
		{"do", 200, "<ListBucketResult>", true, false, false},
		{"oss", 404, "<Code>NoSuchBucket</Code>", false, true, false},
		{"azure", 200, "<EnumerationResults ContainerName=x>", true, false, false},
		{"azure", 404, "ResourceNotFound", false, false, false}, // a container in someone's account: nobody else can create it
		{"firebase-storage", 200, `{"items":[{"name":"a"}]}`, true, false, false},
		{"firebase-storage", 403, `{"error":{"code":403}}`, false, false, false},
		{"firebase", 200, `{"users":true}`, true, false, false},
		{"firebase", 200, "null", true, false, true},
		{"firebase", 401, `{"error":"Permission denied"}`, false, false, false},
	}
	for _, c := range cases {
		br := BucketResult{Provider: c.provider}
		classifyStorage(&br, c.status, c.body)
		if !br.Checked || br.Public != c.public || br.Missing != c.missing || br.Empty != c.empty {
			t.Errorf("%s %d %q: %+v", c.provider, c.status, c.body, br)
		}
	}
}

func TestPageSecretsAreMaskedAndPrecise(t *testing.T) {
	body := []byte(`var cfg = {stripe: "` + fakeStripe + `", pub: "` + fakePub + `", aws: "` + fakeAWS + `"}; var again = "` + fakeStripe + `";`)
	hits := pageSecrets(body, "https://www.example.test/app.js")
	if len(hits) != 2 {
		t.Fatalf("want the Stripe secret key and the AWS key once each, got %+v", hits)
	}
	for _, h := range hits {
		if strings.Contains(h.Masked, fakeStripe) || strings.Contains(h.Masked, fakeAWS) || len(h.Masked) > 40 || h.Hash == "" {
			t.Errorf("not masked: %+v", h)
		}
		if h.Severity != "high" || h.Where != "https://www.example.test/app.js" {
			t.Errorf("%+v", h)
		}
	}
}

// End to end: a site's page and its own script link to storage and contain a key. Every linked
// bucket is checked once, a public database and a missing bucket are reported, a supplier's bucket
// is rated lower, and no finding holds the key itself.
func TestLinkedStorageAndSecretsFindings(t *testing.T) {
	l := newWebLab(t)
	mux := http.NewServeMux()
	listing := `<?xml version="1.0"?><ListBucketResult><Name>x</Name></ListBucketResult>`
	mux.HandleFunc("/s3/example-media/", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, listing) })
	mux.HandleFunc("/s3/vendor-cdn/", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, listing) })
	mux.HandleFunc("/s3/example-gone/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code></Error>`)
	})
	mux.HandleFunc("/x/example-app-default-rtdb.firebaseio.com/.json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("shallow") != "true" {
			t.Error("the database must only be asked for its top-level keys")
		}
		_, _ = fmt.Fprint(w, `{"users":true,"orders":true}`)
	})
	bs := httptest.NewServer(mux)
	defer bs.Close()
	l.bucketBase = bs.URL
	l.setProber()

	l.host("app.example.test", "203.0.113.40")
	cert := l.ca.leaf(t, -time.Hour, 90*24*time.Hour, "app.example.test")
	l.serve("203.0.113.40", 443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = fmt.Fprint(w, `<html><head><title>App</title><script src="/static/app.js"></script></head><body>
<img src="https://example-media.s3.amazonaws.com/logo.png"><img src="https://vendor-cdn.s3.amazonaws.com/lib.png"></body></html>`)
		case "/static/app.js":
			_, _ = fmt.Fprint(w, `const k = "`+fakeStripe+`"; const db = "https://example-app-default-rtdb.firebaseio.com"; load("https://example-gone.s3.amazonaws.com/widget.js");`)
		default:
			http.NotFound(w, r)
		}
	}), &cert, tls.VersionTLS12)

	tg := l.h.addTarget("example.test", "AS64500")
	l.h.scanN(tg.ID, 1)

	pub := l.findingFor("bucket-public", "example-media")
	if pub == nil || pub.Severity != "high" || !strings.Contains(pub.Detail, "linked from https://app.example.test/") {
		t.Errorf("own linked bucket: %+v (open: %v)", pub, l.openKinds())
	}
	if v := l.findingFor("bucket-public", "vendor-cdn"); v == nil || v.Severity != "medium" || !strings.Contains(v.Detail, "Check whether it is yours") {
		t.Errorf("supplier's bucket should be Medium with a note: %+v", v)
	}
	if g := l.findingFor("bucket-takeover", "example-gone"); g == nil || !strings.Contains(g.Detail, "scripts included") {
		t.Errorf("missing bucket the site loads from: %+v", g)
	}
	if f := l.findingFor("firebase-public", "example-app-default-rtdb"); f == nil || f.Severity != "high" {
		t.Errorf("readable Firebase database: %+v", f)
	}
	sec := l.findingFor("secret-in-page", "app.example.test")
	if sec == nil || sec.Severity != "high" || !strings.Contains(sec.Detail, "Stripe live secret key") || !strings.Contains(sec.Detail, "/static/app.js") {
		t.Fatalf("secret in the site's script: %+v", sec)
	}
	all, _ := l.h.store.ListFindings("example.test", "")
	for _, f := range all {
		if strings.Contains(f.Detail+f.Host+f.Key, fakeStripe) {
			t.Errorf("a finding stores the secret itself: %s", f.Kind)
		}
	}

	// The key is removed and the database locked: both findings resolve on the next scans.
	l.serve("203.0.113.40", 443, page("App", "nothing here"), &cert, tls.VersionTLS12)
	mux.HandleFunc("/x/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	l.h.scanN(tg.ID, 3)
	if l.findingFor("secret-in-page", "app.example.test") != nil {
		t.Error("the secret finding should resolve once the page no longer has the key")
	}
}
