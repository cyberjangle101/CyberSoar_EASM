package main

import (
	"regexp"
	"sort"
	"strings"
)

// ---- EASM-CLOUD-001, -002 and -008: cloud storage named in DNS or linked from the organisation's
// own pages and scripts. Each is checked with one unauthenticated, read-only request to the provider.

// storageRef is a bucket, container or database to check, and where it was found.
type storageRef struct {
	Provider string // s3, gcs, do, oss, azure, firebase-storage, firebase
	Name     string // the bucket; "account/container" for Azure; the database host for Firebase
	Via      string // the page or script that links to it ("" = found in DNS)
}

// claimableStorage are the providers whose bucket names are global and first come, first served:
// a deleted one can be created by anyone, so a name or a page that still points at it can be taken over.
var claimableStorage = map[string]bool{"s3": true, "gcs": true, "do": true, "oss": true}

var (
	s3HostRe = regexp.MustCompile(`^(.+?)\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com\.?$`)
	doHostRe = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*[a-z0-9])\.([a-z]{3}[0-9])(\.cdn)?\.digitaloceanspaces\.com\.?$`)
	osHostRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]*[a-z0-9])\.(oss-[a-z0-9-]+)(-internal)?\.aliyuncs\.com\.?$`)
	gcsVhRe  = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]*[a-z0-9])\.storage\.googleapis\.com\.?$`)
)

// Storage addresses as they appear in HTML and JavaScript, matched against the lower-cased text.
var pageStorageRes = []struct {
	provider string
	re       *regexp.Regexp
	name     func(m []string) string
}{
	{"s3", regexp.MustCompile(`https?://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\b`), func(m []string) string { return m[1] }},
	{"s3", regexp.MustCompile(`https?://s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/`), func(m []string) string { return m[1] }},
	{"gcs", regexp.MustCompile(`https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/`), func(m []string) string { return m[1] }},
	{"gcs", regexp.MustCompile(`https?://([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b`), func(m []string) string { return m[1] }},
	{"do", regexp.MustCompile(`https?://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.([a-z]{3}[0-9])(?:\.cdn)?\.digitaloceanspaces\.com\b`), func(m []string) string { return m[1] + "." + m[2] }},
	{"oss", regexp.MustCompile(`https?://([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.(oss-[a-z0-9-]+)\.aliyuncs\.com\b`), func(m []string) string { return m[1] + "." + m[2] }},
	{"azure", regexp.MustCompile(`https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?)[/?"'\s]`), func(m []string) string { return m[1] + "/" + m[2] }},
	{"firebase-storage", regexp.MustCompile(`firebasestorage\.googleapis\.com/v0/b/([a-z0-9][a-z0-9._-]{1,200}[a-z0-9])/`), func(m []string) string { return m[1] }},
	{"firebase-storage", regexp.MustCompile(`storagebucket["']?\s*:\s*["']([a-z0-9][a-z0-9.-]{1,200}\.(?:appspot\.com|firebasestorage\.app))["']`), func(m []string) string { return m[1] }},
	{"firebase", regexp.MustCompile(`https?://([a-z0-9][a-z0-9-]{1,62}[a-z0-9]\.firebaseio\.com)\b`), func(m []string) string { return m[1] }},
	{"firebase", regexp.MustCompile(`https?://([a-z0-9][a-z0-9-]{1,62}[a-z0-9]\.[a-z0-9-]+\.firebasedatabase\.app)\b`), func(m []string) string { return m[1] }},
}

// pageStorage lists the cloud storage a page or script links to, at most 20 per file.
func pageStorage(body []byte, via string) []storageRef {
	text := strings.ToLower(string(body))
	var out []storageRef
	seen := map[string]bool{}
	for _, ps := range pageStorageRes {
		for _, m := range ps.re.FindAllStringSubmatch(text, 50) {
			name := ps.name(m)
			if k := ps.provider + "/" + name; !seen[k] && len(out) < 20 {
				seen[k] = true
				out = append(out, storageRef{Provider: ps.provider, Name: name, Via: via})
			}
		}
	}
	return out
}

// bucketsFor derives the storage buckets that DNS names point to.
func bucketsFor(host string, cnames []string) []struct{ Provider, Name string } {
	var out []struct{ Provider, Name string }
	seen := map[string]bool{}
	add := func(p, n string) {
		if k := p + "/" + n; n != "" && !seen[k] {
			seen[k] = true
			out = append(out, struct{ Provider, Name string }{p, n})
		}
	}
	for _, c := range cnames {
		c = strings.ToLower(strings.TrimSuffix(c, "."))
		switch {
		case c == "c.storage.googleapis.com":
			add("gcs", strings.ToLower(host))
		case s3HostRe.MatchString(c + "."):
			add("s3", s3HostRe.FindStringSubmatch(c + ".")[1])
		case doHostRe.MatchString(c):
			m := doHostRe.FindStringSubmatch(c)
			add("do", m[1]+"."+m[2])
		case osHostRe.MatchString(c):
			m := osHostRe.FindStringSubmatch(c)
			add("oss", m[1]+"."+m[2])
		case gcsVhRe.MatchString(c):
			add("gcs", gcsVhRe.FindStringSubmatch(c)[1])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider+out[i].Name < out[j].Provider+out[j].Name })
	return out
}

// storageListURL is the unauthenticated, read-only request that shows whether anyone can list a
// bucket (or read a database). The "" result means the provider is not checked.
func (p *Prober) storageListURL(provider, name string) string {
	var u string
	switch provider {
	case "s3":
		return p.urls.s3(name)
	case "gcs":
		return p.urls.gcs(name)
	case "do": // name is bucket.region
		u = "https://" + name + ".digitaloceanspaces.com/"
	case "oss": // name is bucket.oss-region
		u = "https://" + name + ".aliyuncs.com/"
	case "azure": // name is account/container
		acct, container, ok := strings.Cut(name, "/")
		if !ok {
			return ""
		}
		u = "https://" + acct + ".blob.core.windows.net/" + container + "?restype=container&comp=list&maxresults=1"
	case "firebase-storage":
		u = "https://firebasestorage.googleapis.com/v0/b/" + name + "/o?maxResults=1"
	case "firebase": // shallow: only the top-level key names, never the data under them
		u = "https://" + name + "/.json?shallow=true"
	default:
		return ""
	}
	if p.urls.rewrite != nil {
		return p.urls.rewrite(u)
	}
	return u
}

// classifyStorage reads the provider's answer.
func classifyStorage(br *BucketResult, status int, body string) {
	switch br.Provider {
	case "azure":
		br.Checked = status == 200 || status == 403 || status == 404 || status == 409
		br.Public = status == 200 && strings.Contains(body, "<EnumerationResults")
	case "firebase-storage":
		br.Checked = status == 200 || status == 400 || status == 401 || status == 403 || status == 404
		br.Public = status == 200 && (strings.Contains(body, `"items"`) || strings.Contains(body, `"prefixes"`))
	case "firebase":
		br.Checked = status == 200 || status == 401 || status == 403 || status == 404 || status == 423
		if status == 200 {
			br.Public = true
			br.Empty = strings.TrimSpace(body) == "null"
		}
	default: // the S3 API, which Google Cloud Storage, DigitalOcean Spaces and Alibaba OSS also speak
		switch {
		case status == 200 && strings.Contains(body, "<ListBucketResult"):
			br.Checked, br.Public = true, true
		case status == 404 && strings.Contains(body, "NoSuchBucket"):
			br.Checked, br.Missing = true, claimableStorage[br.Provider]
		case status == 403 || status == 200 || status == 301 || status == 307:
			br.Checked = true // exists, and is not listable
		}
	}
}

func bucketProvider(p string) string {
	switch p {
	case "s3":
		return "Amazon S3"
	case "gcs":
		return "Google Cloud Storage"
	case "do":
		return "DigitalOcean Spaces"
	case "oss":
		return "Alibaba Cloud OSS"
	case "azure":
		return "Azure Blob Storage"
	case "firebase-storage":
		return "Firebase Storage"
	case "firebase":
		return "Firebase Realtime Database"
	}
	return p
}

// storageNoun is what the provider calls the thing being listed.
func storageNoun(p string) string {
	if p == "azure" {
		return "container"
	}
	return "bucket"
}

// domainLabel is the name part of the domain's registrable domain ("acme" for shop.acme.co.uk), to
// tell a bucket named after the organisation from one that belongs to a supplier.
func domainLabel(domain string) string {
	reg := registrable(domain)
	if reg == "" {
		reg = domain
	}
	l, _, _ := strings.Cut(strings.ToLower(reg), ".")
	return l
}
