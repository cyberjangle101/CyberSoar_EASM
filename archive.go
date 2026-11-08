package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Archived exposures (EASM-WEB-013): files and pages from the organisation's own hosts that
// the Wayback Machine has kept, such as .env files, database dumps, logs, admin consoles,
// spreadsheets and documents. This is the passive half of "search engine dorking"
// (filetype:pdf site:example.com and the like): the search engines' own APIs are closing or
// forbid automated queries, while the archive answers one query for a whole domain.
// Nothing is sent to the organisation's servers. An archived copy stays public even after
// the file is removed, which is why it is reported.

const (
	archiveLimit   = 5000 // archived URLs read per domain
	archiveListMax = 5    // URLs quoted in one finding
)

// archiveCategory is one kind of archived file, matched against the URL path.
type archiveCategory struct {
	ID, Label, Severity string
	re                  *regexp.Regexp
}

var archiveCategories = []archiveCategory{
	{"secrets", "configuration or secrets files", "medium", regexp.MustCompile(`(?i)(/\.env(\.[a-z0-9_-]+)?|/\.git/(config|head)|/\.htpasswd|/\.npmrc|/\.pypirc|/\.aws/credentials|/\.s3cfg|/\.docker/config\.json|/web\.config|/wp-config\.php\S*|/config\.(json|ya?ml|ini|php\.bak)|/(id_rsa|id_dsa|id_ecdsa|id_ed25519)|\.(pem|key|ppk|p12|pfx|kdbx))$`)},
	{"backups", "database dumps or backups", "medium", regexp.MustCompile(`(?i)\.(sql|sql\.gz|dump|bak|backup|old|orig|db|sqlite3?|mdb)$`)},
	{"logs", "log files", "low", regexp.MustCompile(`(?i)(\.log|/error_log|/access_log)$`)},
	{"consoles", "admin or diagnostic pages", "low", regexp.MustCompile(`(?i)/(phpmyadmin|adminer\.php|server-status|server-info|actuator(/[a-z]+)?|manager/html|_profiler|elmah\.axd|trace\.axd|phpinfo\.php|info\.php)/?$`)},
	{"archives", "compressed archives", "low", regexp.MustCompile(`(?i)\.(zip|tar|tar\.gz|tgz|gz|7z|rar)$`)},
	{"data", "spreadsheets or data exports", "low", regexp.MustCompile(`(?i)\.(xlsx?|xlsm|csv|tsv|ods)$`)},
	{"documents", "documents", "info", regexp.MustCompile(`(?i)\.(pdf|docx?|pptx?|odt|rtf)$`)},
}

// archiveCDXFilter narrows the archive's answer on its side to URLs that could fall in a
// category (the CDX server matches the whole "original" field with a Java regular
// expression); classifyArchived then decides precisely.
const archiveCDXFilter = `original:(?i).*(\.(env[^/]*|htpasswd|npmrc|pypirc|s3cfg|config|ya?ml|ini|bak|pem|key|ppk|p12|pfx|kdbx|sql|gz|dump|backup|old|orig|db|sqlite3?|mdb|log|zip|tar|tgz|7z|rar|xlsx?|xlsm|csv|tsv|ods|pdf|docx?|pptx?|odt|rtf|axd)` +
	`|/((adminer|phpinfo|info)\.php|wp-config\.php[^/]*|config\.json|config\.php\.bak|\.docker/config\.json|\.git/(config|head)|\.aws/credentials` +
	`|id_rsa|id_dsa|id_ecdsa|id_ed25519|error_log|access_log|phpmyadmin|server-status|server-info|actuator(/[a-z]+)?|manager/html|_profiler)/?)(\?.*)?$`

// archivedURL is one archived capture.
type archivedURL struct {
	URL, Host, Path string
	At              time.Time
}

// ArchivedFiles asks the Wayback Machine for archived URLs under root (and its subdomains)
// that look like files or pages that should not be public.
func (d *Discoverer) ArchivedFiles(ctx context.Context, root string) ([]archivedURL, error) {
	u := d.urls.wayback + "?url=" + url.QueryEscape(root) + "&matchType=domain&output=json&fl=original,timestamp" +
		"&collapse=urlkey&filter=statuscode:200&filter=" + url.QueryEscape(archiveCDXFilter) + "&limit=" + fmt.Sprint(archiveLimit)
	var out []archivedURL
	err := d.getWithRetry(ctx, "archive-exposure", u, nil, 2, 10*time.Second, time.Minute, 120*time.Second, func(r io.Reader) (err error) {
		out, err = parseArchived(r, root)
		return err
	})
	return out, err
}

// parseArchived reads CDX JSON rows (a header, then original and timestamp) and keeps the
// captures on root or its subdomains.
func parseArchived(r io.Reader, root string) ([]archivedURL, error) {
	var rows [][]string
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, err
	}
	var out []archivedURL
	for i, row := range rows {
		if i == 0 || len(row) < 2 {
			continue
		}
		raw := row[0]
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host != root && !strings.HasSuffix(host, "."+root) {
			continue
		}
		at, _ := time.Parse("20060102150405", row[1])
		out = append(out, archivedURL{URL: raw, Host: host, Path: u.EscapedPath(), At: at})
	}
	return out, nil
}

// classifyArchived returns the category of an archived URL, or nil.
func classifyArchived(a archivedURL) *archiveCategory {
	p := strings.TrimSuffix(a.Path, "/")
	if p == "" {
		return nil
	}
	for i := range archiveCategories {
		if archiveCategories[i].re.MatchString(p) || archiveCategories[i].re.MatchString(p+"/") {
			return &archiveCategories[i]
		}
	}
	return nil
}

// archiveFinding is one host's archived URLs of one category.
type archiveFinding struct {
	Key, Host, Severity, Detail string
}

// archiveFindings groups the archived URLs by host and category, one finding each.
func archiveFindings(urls []archivedURL) []archiveFinding {
	type group struct {
		cat  *archiveCategory
		host string
		urls []archivedURL
	}
	groups := map[string]*group{}
	for _, a := range urls {
		c := classifyArchived(a)
		if c == nil {
			continue
		}
		k := "archive:" + a.Host + ":" + c.ID
		g := groups[k]
		if g == nil {
			g = &group{cat: c, host: a.Host}
			groups[k] = g
		}
		g.urls = append(g.urls, a)
	}
	out := make([]archiveFinding, 0, len(groups))
	for k, g := range groups {
		sort.Slice(g.urls, func(i, j int) bool { return g.urls[i].At.After(g.urls[j].At) }) // newest first
		var b strings.Builder
		fmt.Fprintf(&b, "The Wayback Machine holds %d archived %s from %s", len(g.urls), g.cat.Label, g.host)
		if !g.urls[0].At.IsZero() {
			fmt.Fprintf(&b, ", the latest archived on %s", g.urls[0].At.Format("2006-01-02"))
		}
		b.WriteString(":")
		for i, a := range g.urls {
			if i == archiveListMax {
				fmt.Fprintf(&b, " and %d more", len(g.urls)-archiveListMax)
				break
			}
			fmt.Fprintf(&b, " %s (copy: https://web.archive.org/web/%s/%s)", a.URL, a.At.Format("20060102150405"), a.URL)
			if i < len(g.urls)-1 && i < archiveListMax-1 {
				b.WriteString(";")
			}
		}
		b.WriteString(". Archived copies stay public after a file is removed. Check what each held and whether it is still on the site.")
		out = append(out, archiveFinding{Key: k, Host: g.host, Severity: g.cat.Severity, Detail: b.String()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
