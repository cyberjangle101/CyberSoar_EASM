package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestClassifyArchived(t *testing.T) {
	for path, want := range map[string]string{
		"/.env":                    "secrets",
		"/.env.production":         "secrets",
		"/.git/config":             "secrets",
		"/wp-config.php.bak":       "secrets",
		"/keys/server.pem":         "secrets",
		"/backup/db.sql.gz":        "backups",
		"/old/site.bak":            "backups",
		"/logs/app.log":            "logs",
		"/phpmyadmin/":             "consoles",
		"/actuator/env":            "consoles",
		"/server-status":           "consoles",
		"/downloads/site.zip":      "archives",
		"/exports/customers.xlsx":  "data",
		"/reports/annual-2025.pdf": "documents",
		"/index.html":              "",
		"/":                        "",
		"/blog/environment.html":   "",
	} {
		got := ""
		if c := classifyArchived(archivedURL{Path: path}); c != nil {
			got = c.ID
		}
		if got != want {
			t.Errorf("classifyArchived(%q) = %q, want %q", path, got, want)
		}
	}
}

// Every path a category matches must also pass the filter sent to the archive, or the
// archive would never return it. (Java and Go agree on the constructs used here.)
func TestArchiveCDXFilterCoversCategories(t *testing.T) {
	re := regexp.MustCompile("^" + strings.TrimPrefix(archiveCDXFilter, "original:") + "$")
	for _, p := range []string{"/.env", "/.env.local", "/.git/config", "/.git/HEAD", "/.htpasswd", "/.aws/credentials", "/wp-config.php.bak", "/id_rsa",
		"/a.pem", "/db.sql", "/db.sql.gz", "/x.bak", "/app.log", "/error_log", "/phpmyadmin/", "/adminer.php", "/server-status", "/actuator/health",
		"/manager/html", "/site.zip", "/a.xlsx", "/a.csv", "/a.pdf", "/a.docx", "/a.pdf?download=1"} {
		u := "https://www.example.test" + p
		if !re.MatchString(u) {
			t.Errorf("the archive filter would drop %s", u)
		}
		if c := classifyArchived(archivedURL{Path: strings.SplitN(p, "?", 2)[0]}); c == nil {
			t.Errorf("%s matches the archive filter but no category", p)
		}
	}
	if re.MatchString("https://www.example.test/about.php") {
		t.Error("ordinary pages should not use up the archive's result limit")
	}
}

func TestArchiveFindings(t *testing.T) {
	body := `[["original","timestamp"],
		["https://www.example.test/.env","20250102030405"],
		["http://www.example.test/.env.bak","20260102030405"],
		["https://example.test/reports/a.pdf","20240101000000"],
		["https://other.test/.env","20260101000000"],
		["https://www.example.test/about.html","20260101000000"]]`
	urls, err := parseArchived(strings.NewReader(body), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 4 {
		t.Fatalf("parseArchived kept %d URLs, want 4 (other.test is out of scope)", len(urls))
	}
	got := archiveFindings(urls)
	if len(got) != 2 {
		t.Fatalf("archiveFindings = %+v, want 2 (secrets on www, documents on the root)", got)
	}
	sec := got[1]
	if sec.Key != "archive:www.example.test:secrets" || sec.Severity != "medium" || sec.Host != "www.example.test" {
		t.Errorf("secrets finding: %+v", sec)
	}
	for _, want := range []string{"2 archived configuration or secrets files", "latest archived on 2026-01-02", "https://web.archive.org/web/20260102030405/http://www.example.test/.env.bak"} {
		if !strings.Contains(sec.Detail, want) {
			t.Errorf("detail is missing %q: %s", want, sec.Detail)
		}
	}
	if doc := got[0]; doc.Key != "archive:example.test:documents" || doc.Severity != "info" {
		t.Errorf("documents finding: %+v", doc)
	}
}

// A scan with the check on raises one finding per host and kind, and closes it when the
// archive answers without those files.
func TestArchivedExposureScan(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	files := `[["original","timestamp"],["https://www.example.test/backup/site.sql","20260301000000"]]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("url") != "example.test" || q.Get("matchType") != "domain" || len(q["filter"]) != 2 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, files)
	}))
	t.Cleanup(srv.Close)
	newScanner := h.eng.newScanner
	h.eng.newScanner = func(cfg *Config, res *Resolver) *Scanner {
		sc := newScanner(cfg, res)
		sc.disc.urls.wayback = srv.URL
		return sc
	}
	st, _ := h.store.LoadSettings()
	st.ArchiveExposureEnabled = true
	h.saveSettings(st)

	tg := h.addTarget("example.test", "")
	h.scan(tg.ID)
	open := findingKeys(t, h, "archived-exposure", "open")
	f, ok := open["archive:www.example.test:backups"]
	if !ok || f.Severity != "medium" || !strings.Contains(f.Detail, "site.sql") {
		t.Fatalf("archived backup not reported: %v", fkeys(open))
	}

	files = `[["original","timestamp"]]`
	h.scan(tg.ID)
	if open := findingKeys(t, h, "archived-exposure", "open"); len(open) != 0 {
		t.Errorf("the finding should close once the archive no longer has the file: %v", fkeys(open))
	}
}
