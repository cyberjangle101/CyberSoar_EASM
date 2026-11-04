package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ---- EASM-WEB-012: API keys and other secrets in public pages and scripts

// secretHit is a secret found in a page. The value itself is never kept: only what kind of secret
// it is, where it is, a masked form (its well-known prefix and length) and a short hash so the same
// secret is recognised on the next scan.
type secretHit struct {
	What, Where, Masked, Hash, Severity string
}

// secretPatterns only match token formats that are secret by themselves and unmistakable, so a
// match is worth a person's attention. Keys that are public by design (Stripe publishable keys,
// Google Maps browser keys restricted by referrer) are left out or rated low.
var secretPatterns = []struct {
	What, Severity string
	Shown          int // leading characters that are the token's public prefix, safe to show
	re             *regexp.Regexp
}{
	{"a private key", "high", 0, regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)},
	{"an AWS access key ID", "high", 4, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"a Stripe live secret key", "high", 8, regexp.MustCompile(`\b[rs]k_live_[0-9a-zA-Z]{24,99}\b`)},
	{"a GitHub token", "high", 4, regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b`)},
	{"a Slack token", "high", 5, regexp.MustCompile(`\bxox[abprs]-[0-9A-Za-z-]{10,250}\b`)},
	{"a Slack webhook address", "medium", 33, regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]{6,12}/B[0-9A-Z]{6,12}/[0-9A-Za-z]{20,40}`)},
	{"a SendGrid API key", "high", 3, regexp.MustCompile(`\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b`)},
	{"an OpenAI API key", "high", 8, regexp.MustCompile(`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,250}\b`)},
	{"an Anthropic API key", "high", 7, regexp.MustCompile(`\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,250}\b`)},
	{"a Google API key (check that it is restricted to your sites and the APIs you use)", "low", 4, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
}

// pageSecrets finds secrets in one page or script, at most 10.
func pageSecrets(body []byte, where string) []secretHit {
	var out []secretHit
	seen := map[string]bool{}
	text := string(body)
	for _, sp := range secretPatterns {
		for _, v := range sp.re.FindAllString(text, 10) {
			sum := sha256.Sum256([]byte(v))
			h := fmt.Sprintf("%x", sum[:6])
			if seen[h] || len(out) >= 10 {
				continue
			}
			seen[h] = true
			out = append(out, secretHit{What: sp.What, Where: where, Severity: sp.Severity, Hash: h, Masked: maskSecret(v, sp.Shown)})
		}
	}
	return out
}

// maskSecret shows only the token's public, well-known prefix and its length.
func maskSecret(v string, shown int) string {
	if shown <= 0 {
		return "a PEM private key block"
	}
	return fmt.Sprintf("%s… (%d characters)", v[:min(shown, len(v)/3)], len(v))
}

// pageAsset is a page or script and its address.
type pageAsset struct {
	Where string
	Body  []byte
}

// pageAssets returns the home page and up to five of the site's own scripts, for the storage and
// secret checks. Scripts on other hosts are not fetched: they are someone else's.
func (p *Prober) pageAssets(ctx context.Context, wr *WebResult, home []byte) []pageAsset {
	out := []pageAsset{{wr.URL(), home}}
	n := 0
	for _, m := range scriptSrcRe.FindAllSubmatch(home, 50) {
		u, err := url.Parse(string(m[1]))
		if err != nil || u.Path == "" || (u.Host != "" && !strings.EqualFold(u.Hostname(), wr.Host)) || n >= 5 || ctx.Err() != nil {
			continue
		}
		if !strings.HasPrefix(u.Path, "/") {
			u.Path = "/" + u.Path
		}
		n++
		js, err := p.fetchLimit(ctx, wr.Scheme, wr.Host, wr.IP, wr.Port, u.Path, 4<<20)
		if err != nil || js.Status != 200 {
			continue
		}
		out = append(out, pageAsset{strings.TrimSuffix(wr.URL(), "/") + u.Path, js.Body})
	}
	return out
}
