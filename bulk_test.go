package main

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// Bulk triage: the Type filter lists one kind of finding, the ticked findings are accepted or
// reopened together, each change is audited, and the usual role and CSRF rules apply.
func TestFindingsBulkTriage(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	admin.post("/targets", url.Values{"domain": {"example.test"}, "asns": {"AS64500"}})
	e.scan(1)
	for _, h := range []string{"examp1e.test", "exarnple.test", "example-login.test"} {
		insertFinding(t, e, "lookalike-domain:"+h, "lookalike-domain", h, h+" is registered and looks like example.test", "")
	}
	analyst := e.signedIn("ana", RoleAnalyst)
	viewer := e.signedIn("vic", RoleViewer)

	all, err := e.store.ListFindings("", "open")
	if err != nil || len(all) < 3 {
		t.Fatalf("need at least 3 open findings, have %d (%v)", len(all), err)
	}
	ids := func(fs ...Finding) url.Values {
		v := url.Values{}
		for _, f := range fs {
			v.Add("id", strconv.FormatInt(f.ID, 10))
		}
		return v
	}

	// the page offers the bulk bar to triagers only, with a box per finding
	_, body, _ := analyst.get("/findings")
	if !strings.Contains(body, `action="/findings/bulk"`) || strings.Count(body, `form="bulk"`) != len(all) || !strings.Contains(body, `data-pick-all`) {
		t.Fatalf("bulk bar or tick boxes missing: %d boxes for %d findings", strings.Count(body, `form="bulk"`), len(all))
	}
	if _, body, _ = viewer.get("/findings"); strings.Contains(body, `action="/findings/bulk"`) || strings.Contains(body, `form="bulk"`) {
		t.Error("viewer is shown bulk triage")
	}

	// the Type filter lists each title with its count and narrows the list to it
	title := describeFinding(all[0]).Title
	same := 0
	for _, f := range all {
		if describeFinding(f).Title == title {
			same++
		}
	}
	_, body, _ = analyst.get("/findings?type=" + url.QueryEscape(title))
	if !strings.Contains(body, `selected>`+htmlEsc(title)) || strings.Count(body, `form="bulk"`) != same {
		t.Fatalf("type filter: want %d rows of %q, got %d", same, title, strings.Count(body, `form="bulk"`))
	}
	// a type with nothing left stays chosen and lists nothing, so "tick all" cannot reach other findings
	if _, body, _ = analyst.get("/findings?type=no-such-type"); strings.Contains(body, `form="bulk"`) || !strings.Contains(body, `selected>no-such-type (0)`) || !strings.Contains(body, "No findings match") {
		t.Error("an emptied type filter fell back to listing every finding")
	}

	// refused: viewer, no CSRF, nothing ticked, no reason, a past review date, an unknown action
	pick := ids(all[0], all[1])
	pick.Set("action", "accept")
	pick.Set("reason", "unrelated companies")
	if code, _, _ := viewer.post("/findings/bulk", pick); code != 403 {
		t.Errorf("viewer bulk = %d, want 403", code)
	}
	if code, _, _ := analyst.postRaw("/findings/bulk", pick); code != 403 {
		t.Errorf("bulk without CSRF = %d, want 403", code)
	}
	for name, v := range map[string]url.Values{
		"nothing ticked": {"action": {"accept"}, "reason": {"unrelated companies"}},
		"no reason":      func() url.Values { v := ids(all[0], all[1]); v.Set("action", "accept"); return v }(),
		"past date": func() url.Values {
			v := ids(all[0], all[1])
			v.Set("action", "accept")
			v.Set("reason", "x y z")
			v.Set("until", "2001-01-01")
			return v
		}(),
		"bad action": func() url.Values { v := ids(all[0], all[1]); v.Set("action", "delete"); return v }(),
	} {
		v.Set("next", "/findings")
		if code, _, r := analyst.post("/findings/bulk", v); code != 303 || loc(r) != "/findings" {
			t.Errorf("%s: %d %s", name, code, loc(r))
		}
		if findingByID(t, e, all[0].ID).Status != "open" || findingByID(t, e, all[1].ID).Status != "open" {
			t.Fatalf("%s: findings changed", name)
		}
	}
	tooMany := url.Values{"action": {"accept"}, "reason": {"x y z"}}
	for i := 1; i <= bulkMax+1; i++ {
		tooMany.Add("id", strconv.Itoa(i))
	}
	analyst.post("/findings/bulk", tooMany)
	if findingByID(t, e, all[0].ID).Status != "open" {
		t.Fatal("more than bulkMax findings were changed")
	}

	// accept two: both recorded with the one reason, audited one by one, the third untouched
	pick.Del("csrf") // the refused posts above filled in other sessions' tokens
	pick.Set("next", "/findings?status=open")
	if code, _, r := analyst.post("/findings/bulk", pick); code != 303 || loc(r) != "/findings?status=open" {
		t.Fatalf("bulk accept: %d %s", code, loc(r))
	}
	for _, f := range all[:2] {
		got := findingByID(t, e, f.ID)
		if got.Status != "ack" || got.AckBy != "ana" || got.AckReason != "unrelated companies" {
			t.Fatalf("finding %d not accepted: %+v", f.ID, got)
		}
	}
	if findingByID(t, e, all[2].ID).Status != "open" {
		t.Fatal("an unticked finding was changed")
	}
	_, body, _ = analyst.get("/findings")
	if !strings.Contains(body, "Risk accepted for 2 findings.") {
		t.Error("no confirmation of the bulk accept")
	}
	_, au, _ := admin.get("/audit?action=finding.accept")
	if strings.Count(au, "bulk action on 2 selected") != 2 {
		t.Errorf("want two audited bulk accepts, got %d", strings.Count(au, "bulk action on 2 selected"))
	}

	// accepting again skips findings that are no longer open and says so
	again := ids(all[0], all[2])
	again.Set("action", "accept")
	again.Set("reason", "second batch")
	analyst.post("/findings/bulk", again)
	if got := findingByID(t, e, all[0].ID); got.AckReason != "unrelated companies" {
		t.Error("an accepted finding was re-accepted with a new reason")
	}
	if findingByID(t, e, all[2].ID).Status != "ack" {
		t.Error("the open finding in the second batch was not accepted")
	}
	if _, body, _ = analyst.get("/findings"); !strings.Contains(body, "Risk accepted for 1 finding. 1 skipped (not open).") {
		t.Error("skipped findings not reported")
	}

	// reopen all three together
	back := ids(all[0], all[1], all[2])
	back.Set("action", "reopen")
	analyst.post("/findings/bulk", back)
	for _, f := range all[:3] {
		if got := findingByID(t, e, f.ID); got.Status != "open" || got.AckReason != "" {
			t.Fatalf("finding %d not reopened: %+v", f.ID, got)
		}
	}
	if _, au, _ = admin.get("/audit?action=finding.reopen"); strings.Count(au, "bulk action on 3 selected") != 3 {
		t.Error("bulk reopens not audited one by one")
	}
}

// htmlEsc is how html/template writes a title into an attribute or text.
func htmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;").Replace(s)
}
