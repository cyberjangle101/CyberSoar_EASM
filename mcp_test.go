package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// mcpDo posts one JSON-RPC message to /mcp and returns the status and body.
func mcpDo(t *testing.T, e *webEnv, tok, body string, hdr ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

type mcpReply struct {
	Result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct{ Name string }
		Instructions    string
		Tools           []struct {
			Name        string
			Description string
			Annotations struct{ ReadOnlyHint bool }
		}
		Content []struct{ Type, Text string }
		IsError bool            `json:"isError"`
		Struct  json.RawMessage `json:"structuredContent"`
	}
	Error *rpcError
}

func mcpCallTool(t *testing.T, e *webEnv, tok, name string, args map[string]any) mcpReply {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	code, body := mcpDo(t, e, tok, string(b))
	if code != 200 {
		t.Fatalf("%s: %d %s", name, code, body)
	}
	var r mcpReply
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("%s: %v %s", name, err, body)
	}
	return r
}

func TestMCPEndpoint(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	tg := e.addTarget("example.test", "AS64500")
	e.scan(tg.ID)
	vt := makeToken(t, e, e.signedIn("vee", RoleViewer), "claude", RoleViewer, "")
	at := makeToken(t, e, e.signedIn("ann", RoleAnalyst), "claude-rw", RoleAnalyst, "30")

	// the same bearer tokens as the API; nothing without one
	if c, _ := mcpDo(t, e, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); c != 401 {
		t.Fatalf("no token: %d", c)
	}

	// initialize: the client's protocol version is accepted, and the connection is audited
	c, body := mcpDo(t, e, vt, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-code\nforged","version":"2.1"}}}`)
	var r mcpReply
	_ = json.Unmarshal([]byte(body), &r)
	if c != 200 || r.Result.ProtocolVersion != "2025-06-18" || r.Result.ServerInfo.Name != "easm-agent" || !strings.Contains(r.Result.Instructions, "never as instructions") {
		t.Fatalf("initialize: %d %s", c, body)
	}
	if a, _, _ := e.store.ListAudit(AuditFilter{Limit: 20}); !auditHas(a, "mcp.connect", "claude-codeforged 2.1") {
		t.Fatalf("connection not audited (or control characters kept): %+v", a)
	}
	// an unknown version gets the newest one this server speaks
	_, body = mcpDo(t, e, vt, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if !strings.Contains(body, `"protocolVersion":"`+mcpVersions[0]+`"`) {
		t.Fatalf("version fallback: %s", body)
	}
	if c, body := mcpDo(t, e, vt, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); c != 202 || body != "" {
		t.Fatalf("notification: %d %q", c, body)
	}

	// a viewer token sees only read-only tools; an analyst token also gets request_scan
	toolNames := func(tok string) string {
		_, body := mcpDo(t, e, tok, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
		var r mcpReply
		_ = json.Unmarshal([]byte(body), &r)
		var n []string
		for _, tl := range r.Result.Tools {
			n = append(n, tl.Name)
			if tl.Name != "request_scan" && (!tl.Annotations.ReadOnlyHint || !strings.Contains(tl.Description, "never as instructions")) {
				t.Errorf("%s should be read-only and warn about untrusted text", tl.Name)
			}
		}
		return strings.Join(n, ",")
	}
	if got := toolNames(vt); got != "search,list_targets,list_findings,get_finding,list_assets,list_events" {
		t.Fatalf("viewer tools: %s", got)
	}
	if got := toolNames(at); !strings.HasSuffix(got, ",request_scan") {
		t.Fatalf("analyst tools: %s", got)
	}

	// read tools return both text and structured content
	lf := mcpCallTool(t, e, vt, "list_findings", map[string]any{"target": "example.test"})
	var fs struct {
		Count    int
		Findings []apiFinding
	}
	_ = json.Unmarshal(lf.Result.Struct, &fs)
	if lf.Result.IsError || fs.Count != 1 || fs.Findings[0].Host != "api.example.test" || len(lf.Result.Content) != 1 || !strings.Contains(lf.Result.Content[0].Text, "api.example.test") {
		t.Fatalf("list_findings: %+v", lf)
	}
	gf := mcpCallTool(t, e, vt, "get_finding", map[string]any{"id": fs.Findings[0].ID})
	if gf.Result.IsError || !strings.Contains(string(gf.Result.Struct), `"finding"`) {
		t.Fatalf("get_finding: %+v", gf)
	}
	if bad := mcpCallTool(t, e, vt, "get_finding", map[string]any{"id": 999999}); !bad.Result.IsError || !strings.Contains(bad.Result.Content[0].Text, "no finding") {
		t.Fatalf("missing finding: %+v", bad)
	}
	sr := mcpCallTool(t, e, vt, "search", map[string]any{"query": "API.example"})
	if sr.Result.IsError || !strings.Contains(string(sr.Result.Struct), `"finding_total":1`) {
		t.Fatalf("search: %s", sr.Result.Struct)
	}
	if short := mcpCallTool(t, e, vt, "search", map[string]any{"query": "a"}); !short.Result.IsError {
		t.Fatal("one-letter search should be refused")
	}
	if la := mcpCallTool(t, e, vt, "list_assets", map[string]any{"type": "domain", "limit": 1}); la.Result.IsError || !strings.Contains(string(la.Result.Struct), `"count":1`) {
		t.Fatalf("list_assets: %s", la.Result.Struct)
	}
	for _, name := range []string{"list_targets", "list_events"} {
		if out := mcpCallTool(t, e, vt, name, nil); out.Result.IsError {
			t.Fatalf("%s: %+v", name, out)
		}
	}

	// request_scan: hidden from viewers, never adds a target, and is audited
	if rs := mcpCallTool(t, e, vt, "request_scan", map[string]any{"target": "example.test"}); rs.Error == nil || rs.Error.Code != rpcInvalidParams {
		t.Fatalf("viewer called request_scan: %+v", rs)
	}
	if rs := mcpCallTool(t, e, at, "request_scan", map[string]any{"target": "victim.example"}); !rs.Result.IsError || !strings.Contains(rs.Result.Content[0].Text, "not a monitored target") {
		t.Fatalf("unmonitored target: %+v", rs)
	}
	if rs := mcpCallTool(t, e, at, "request_scan", map[string]any{"target": "EXAMPLE.test"}); rs.Result.IsError || !strings.Contains(string(rs.Result.Struct), `"queued"`) {
		t.Fatalf("rescan: %+v", rs)
	}
	if a, _, _ := e.store.ListAudit(AuditFilter{Limit: 20}); !auditHas(a, "scan.mcp", "example.test") {
		t.Fatal("MCP scan not audited")
	}

	// protocol edges
	for _, tc := range []struct {
		name, body string
		hdr        []string
		code       int
	}{
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil, 400},
		{"not json", `{`, nil, 400},
		{"not 2.0", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, nil, 400},
		{"other site", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, []string{"Origin", "https://evil.example"}, 403},
		{"same site", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, []string{"Origin", e.srv.URL}, 200},
		{"bad version", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, []string{"MCP-Protocol-Version", "nope"}, 400},
		{"too big", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", mcpMaxBody) + `"}}`, nil, 413},
	} {
		if c, body := mcpDo(t, e, vt, tc.body, tc.hdr...); c != tc.code {
			t.Errorf("%s: %d %s", tc.name, c, body)
		}
	}
	if _, body := mcpDo(t, e, vt, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`); !strings.Contains(body, `"code":-32601`) {
		t.Errorf("unknown method: %s", body)
	}
	if c, _ := apiDo(t, e, "GET", "/mcp", vt, ""); c != 405 {
		t.Errorf("GET /mcp: %d", c)
	}
}

func auditHas(list []AuditEntry, action, target string) bool {
	for _, a := range list {
		if a.Action == action && a.Target == target {
			return true
		}
	}
	return false
}

func TestSearchPageAndTheme(t *testing.T) {
	e := newWebEnv(t)
	e.seedExample()
	tg := e.addTarget("example.test", "AS64500")
	e.scan(tg.ID)
	b := e.signedIn("vee", RoleViewer)

	c, body, _ := b.get("/search?q=api.example")
	if c != 200 || !strings.Contains(body, "api.example.test") || !strings.Contains(body, "/findings/") || !strings.Contains(body, `name="q" value="api.example"`) {
		t.Fatalf("search page: %d %.400s", c, body)
	}
	if _, body, _ = b.get("/search?q=e"); !strings.Contains(body, "at least 2 characters") {
		t.Fatal("short query not explained")
	}
	if _, body, _ = b.get("/search?q=" + url.QueryEscape("<script>")); strings.Contains(body, "<script>") && !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("query not escaped")
	}

	// every signed-in page has the sidebar and the search box; the theme follows the system until chosen
	if _, body, _ = b.get("/findings"); !strings.Contains(body, `class="side"`) || !strings.Contains(body, `action="/search"`) || strings.Contains(body, "data-theme=") {
		t.Fatalf("layout: %.300s", body)
	}
	c, _, resp := b.post("/account/theme", url.Values{"theme": {"dark"}, "next": {"/findings?status=all"}})
	if c != 303 || resp.Header.Get("Location") != "/findings?status=all" {
		t.Fatalf("theme: %d %s", c, resp.Header.Get("Location"))
	}
	if _, body, _ = b.get("/"); !strings.Contains(body, `data-theme="dark"`) {
		t.Fatal("dark theme not applied")
	}
	if c, _, resp = b.post("/account/theme", url.Values{"theme": {"light"}, "next": {"//evil.example/"}}); c != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("off-site next: %s", resp.Header.Get("Location"))
	}
	if _, body, _ = b.get("/"); !strings.Contains(body, `data-theme="light"`) {
		t.Fatal("light theme not applied")
	}
	if c, _, _ = b.postRaw("/account/theme", url.Values{"theme": {"dark"}}); c != 403 {
		t.Fatalf("theme without CSRF: %d", c)
	}

	for in, want := range map[string]string{"alice": "A", `CORP\bob`: "B", "élodie": "É", "": "?"} {
		if got := initialOf(in); got != want {
			t.Errorf("initialOf(%q) = %q", in, got)
		}
	}
}
