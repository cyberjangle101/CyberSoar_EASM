package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Brand watch finds look-alikes that the generated variations (lookalike.go) cannot guess:
// domains that contain the brand name, such as acme-login-secure.com, or are one letter
// away from it. They come from two places:
//
//   - Certificate Transparency: a crt.sh search for certificates issued in the last
//     brandCTWindow to names containing a brand word. Almost every phishing site needs
//     HTTPS, so most show up here within minutes of being set up.
//   - A newly registered domains feed the administrator is licensed for (optional): a
//     text file of domain names, one per line, plain, gzip or zip.
//
// The candidates then go through the same checks as the generated ones (checkLookalike):
// registered by someone else, not parked, and able to receive mail or serve a web site.

const (
	brandCTWindow     = 30 * 24 * time.Hour // certificates issued this recently
	brandMinWord      = 4                   // shorter words match far too many unrelated names
	brandTypoMinWord  = 6                   // one-letter differences only for words at least this long
	brandMaxCands     = 500                 // per target per scan, so DNS work stays bounded
	nrdRefresh        = 20 * time.Hour      // the feed is published daily
	nrdStale          = 3 * 24 * time.Hour  // a failed refresh keeps the last list this long
	nrdMaxBody        = 256 << 20           // the downloaded file
	nrdMaxNames       = 5_000_000           // names kept from one feed
	brandKindCTWord   = "contains your brand name, from certificate logs"
	brandKindCTTypo   = "one letter from your brand name, from certificate logs"
	brandKindFeedWord = "contains your brand name, newly registered"
	brandKindFeedTypo = "one letter from your brand name, newly registered"
)

// brandWords is the target's own name (acme for acme.co.uk) plus the extra words configured,
// lower-cased, de-duplicated, and only those long enough to be distinctive. Hyphens are
// dropped (acme-corp.com watches acmecorp), as brandMatch compares names without them.
func brandWords(root string, extra []string) []string {
	words, _ := brandTerms(root, extra)
	return words
}

// brandTerms returns the brand words and the certificate-log searches for them: each word, and
// also its hyphenated spelling where it had one, since %acmecorp% does not find acme-corp-login.com.
func brandTerms(root string, extra []string) (words, searches []string) {
	seen := map[string]bool{}
	add := func(w string) {
		w = strings.ToLower(strings.TrimSpace(w))
		joined := strings.ReplaceAll(w, "-", "")
		if len(joined) < brandMinWord || !validLabel(w) || !validLabel(joined) {
			return
		}
		if !seen[joined] {
			seen[joined] = true
			words = append(words, joined)
			searches = append(searches, joined)
		}
		if w != joined && !seen[w] {
			seen[w] = true
			searches = append(searches, w)
		}
	}
	if label, _, ok := splitRegistrable(root); ok {
		add(label)
	}
	for _, w := range extra {
		add(w)
	}
	return words, searches
}

// homoglyphFold undoes the digit-for-letter swaps used to dodge simple matching (acrne is
// already a generated variation; this catches 4cme, acm3 and the like inside longer names).
var homoglyphFold = strings.NewReplacer("0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "7", "t", "8", "b", "9", "g")

// brandMatch reports which brand word a registrable domain imitates, and how: its name
// contains the word (after folding look-alike digits), or, for longer words, is a single
// letter different from it.
func brandMatch(registrable string, words []string) (word string, typo, ok bool) {
	label, _, isReg := splitRegistrable(registrable)
	if !isReg {
		return "", false, false
	}
	plain := strings.ReplaceAll(label, "-", "")
	folded := homoglyphFold.Replace(plain)
	for _, w := range words {
		if strings.Contains(plain, w) || strings.Contains(folded, w) {
			return w, false, true
		}
	}
	for _, w := range words {
		if len(w) >= brandTypoMinWord && withinOneEdit(plain, w) {
			return w, true, true
		}
	}
	return "", false, false
}

// withinOneEdit reports whether a and b differ by at most one inserted, deleted or changed letter.
func withinOneEdit(a, b string) bool {
	if a == b {
		return true
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	if len(b)-len(a) > 1 {
		return false
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	if len(a) == len(b) {
		return a[i+1:] == b[i+1:] // one changed letter
	}
	return a[i:] == b[i+1:] // one letter added to the longer one
}

// registrableOf turns a certificate or feed name into the domain someone registered.
func registrableOf(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	name = strings.TrimPrefix(name, "*.")
	if name == "" || strings.ContainsAny(name, " /@:*") {
		return "", false
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return "", false
	}
	return reg, true
}

// brandCandidates gathers this scan's brand-watch candidates for root, leaving out names the
// generated variations already cover and the organisation's own domains.
func (s *Scanner) brandCandidates(ctx context.Context, root string, have []lookalike, own map[string]bool) []lookalike {
	dc := s.cfg.Discover
	words, searches := brandTerms(root, dc.BrandWords)
	if len(words) == 0 || (!dc.BrandCT && dc.NRDFeedURL == "") {
		return nil
	}
	skip := map[string]bool{root: true}
	for _, c := range have {
		skip[c.Domain] = true
	}
	for d := range own {
		skip[d] = true
	}
	found := map[string]string{} // registrable -> kind
	consider := func(name, kindWord, kindTypo string) {
		reg, ok := registrableOf(name)
		if !ok || skip[reg] || found[reg] != "" {
			return
		}
		if _, isTypo, ok := brandMatch(reg, words); ok {
			found[reg] = kindWord
			if isTypo {
				found[reg] = kindTypo
			}
		}
	}
	if dc.BrandCT && s.disc != nil {
		since := time.Now().Add(-brandCTWindow)
		for _, w := range searches {
			names, err := s.disc.BrandCertNames(ctx, w, since)
			s.health.Record("brand-ct", "scan", err == nil, 0, err)
			if err != nil {
				s.log.Warn("brand watch: certificate search failed", "domain", root, "word", w, "err", err)
				continue
			}
			for _, n := range names {
				consider(n, brandKindCTWord, brandKindCTTypo)
			}
		}
	}
	if dc.NRDFeedURL != "" && s.feeds != nil {
		names, err := s.feeds.NRD(ctx, dc.NRDFeedURL, dc.NRDFeedKey)
		if err != nil {
			s.log.Warn("brand watch: newly registered domains feed unavailable", "err", err)
		}
		for _, n := range names {
			consider(n, brandKindFeedWord, brandKindFeedTypo)
		}
	}
	out := make([]lookalike, 0, len(found))
	for d, k := range found {
		out = append(out, lookalike{Domain: d, Kind: k})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	if len(out) > brandMaxCands {
		s.log.Warn("brand watch: too many candidates; checking the first ones only", "domain", root, "found", len(out), "checked", brandMaxCands)
		out = out[:brandMaxCands]
	}
	return out
}

// BrandCertNames asks crt.sh for unexpired certificates issued since the given time to any
// name containing word, and returns those names.
func (d *Discoverer) BrandCertNames(ctx context.Context, word string, since time.Time) ([]string, error) {
	u := d.urls.crtsh + "?q=" + url.QueryEscape("%"+word+"%") + "&output=json&exclude=expired&deduplicate=Y"
	var names []string
	err := d.getWithRetry(ctx, "brand-ct", u, nil, 2, 10*time.Second, time.Minute, 3*time.Minute, func(r io.Reader) (err error) {
		names, err = parseBrandCerts(r, since)
		return err
	})
	return names, err
}

// parseBrandCerts reads crt.sh JSON rows and keeps the names of certificates issued since since.
func parseBrandCerts(r io.Reader, since time.Time) ([]string, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
		NotBefore string `json:"not_before"`
	}
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, row := range rows {
		t, err := time.Parse("2006-01-02T15:04:05", row.NotBefore)
		if err != nil || t.Before(since) {
			continue
		}
		for _, n := range strings.Split(row.NameValue, "\n") {
			if n = strings.TrimSpace(n); n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// nrdCache keeps the newly registered domains feed in memory, shared by every scan.
type nrdCache struct {
	mu      sync.Mutex
	url     string
	fetched time.Time
	names   []string
	hc      *http.Client
}

// NRD returns the newly registered domains from the feed at feedURL, downloading it at most
// about once a day. A failed download keeps the last list for up to nrdStale.
func (f *Feeds) NRD(ctx context.Context, feedURL, key string) ([]string, error) {
	c := &f.nrd
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.url == feedURL && time.Since(c.fetched) < nrdRefresh {
		return c.names, nil
	}
	t0 := time.Now()
	names, err := f.downloadNRD(ctx, feedURL, key)
	f.health.Record("nrd-feed", "scan", err == nil, time.Since(t0), err)
	if err != nil {
		if c.url == feedURL && time.Since(c.fetched) < nrdStale {
			return c.names, err
		}
		return nil, err
	}
	c.url, c.fetched, c.names = feedURL, time.Now(), names
	f.log.Info("newly registered domains feed loaded", "names", len(names))
	return names, nil
}

func (f *Feeds) downloadNRD(ctx context.Context, feedURL, key string) ([]string, error) {
	if u, err := url.Parse(feedURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the feed address must be an https:// URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.ua)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	hc := f.nrd.hc
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, nrdMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > nrdMaxBody {
		return nil, errors.New("feed larger than 256 MB")
	}
	return parseNRD(body)
}

// parseNRD reads a list of domain names, one per line (blank lines and # comments skipped),
// from plain text, gzip, or the first text file in a zip archive.
func parseNRD(body []byte) ([]string, error) {
	var r io.Reader = bytes.NewReader(body)
	switch {
	case bytes.HasPrefix(body, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer func() { _ = gz.Close() }()
		r = io.LimitReader(gz, nrdMaxBody)
	case bytes.HasPrefix(body, []byte("PK\x03\x04")):
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return nil, err
		}
		var file *zip.File
		for _, zf := range zr.File {
			if !zf.FileInfo().IsDir() {
				file = zf
				break
			}
		}
		if file == nil {
			return nil, errors.New("the zip archive has no file in it")
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		r = io.LimitReader(rc, nrdMaxBody)
	}
	var names []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t,;"); i > 0 { // "domain,date" and similar
			line = line[:i]
		}
		names = append(names, strings.ToLower(line))
		if len(names) >= nrdMaxNames {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, errors.New("the feed has no domain names in it")
	}
	return names, nil
}
