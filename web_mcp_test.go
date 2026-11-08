package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"
)

// Settings explains how to connect an assistant, with this agent's own address, and switching
// MCP off refuses every request to /mcp (whatever the token) while the REST API keeps working.
func TestSettingsMCPSection(t *testing.T) {
	e := newWebEnv(t)
	admin := e.signedIn("boss", RoleAdmin)
	tok := makeToken(t, e, admin, "claude", RoleViewer, "")

	code, body, _ := admin.get("/settings")
	host := strings.TrimPrefix(strings.TrimPrefix(e.srv.URL, "https://"), "http://")
	for _, want := range []string{`id="mcp"`, `name="mcp_enabled" checked`, host + `/mcp`, "claude mcp add --transport http easm", "mcp-remote", "request_scan", "No assistant has connected yet",
		`id="mcp-remote"`, "&#34;headers&#34;", "http-only", "Authorization:Bearer &lt;your token&gt;"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
	// mcp-remote sends a ${VAR} in --header as it is, so the agent would refuse it
	if strings.Contains(body, "${") {
		t.Error("a snippet relies on ${...} expansion")
	}

	// the connection appears under Recent connections
	if c, _ := mcpDo(t, e, tok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude-code","version":"9"}}}`); c != 200 {
		t.Fatalf("initialize: %d", c)
	}
	if _, body, _ = admin.get("/settings"); !strings.Contains(body, "claude-code 9") {
		t.Error("the MCP connection is not listed on the Settings page")
	}

	st, _ := e.store.LoadSettings()
	st.MCPEnabled = false
	if c, _, _ := admin.post("/settings", settingsForm(st)); c != 303 {
		t.Fatalf("save: %d", c)
	}
	if got, _ := e.store.LoadSettings(); got.MCPEnabled {
		t.Fatal("unticking the box did not switch MCP off")
	}
	if c, body := mcpDo(t, e, tok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); c != 403 || !strings.Contains(body, "switched off") {
		t.Errorf("MCP off: %d %s", c, body)
	}
	if c, _ := apiDo(t, e, "GET", "/api/v1/findings", tok, ""); c != 200 {
		t.Errorf("the REST API should not be affected by the MCP switch: %d", c)
	}
	if _, body, _ = admin.get("/settings"); strings.Contains(body, `name="mcp_enabled" checked`) {
		t.Error("the box should show MCP as off")
	}
}

// A self-signed agent offers its certificate (never the key) for the assistant's computer to
// trust, and the bridge snippet gains the NODE_EXTRA_CA_CERTS setting for it.
func TestMCPSelfSignedCertificate(t *testing.T) {
	e := newWebEnv(t)
	admin := e.signedIn("boss", RoleAdmin)
	if c, _, _ := admin.get("/settings/certificate.crt"); c != 404 {
		t.Errorf("no certificate keeper: %d, want 404", c)
	}

	k, err := newCertKeeper(t.TempDir(), "127.0.0.1:8080", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.web.certs = k
	code, body, _ := admin.get("/settings")
	for _, want := range []string{`href="/settings/certificate.crt"`, "NODE_EXTRA_CA_CERTS", "&lt;path to easm-agent.crt&gt;"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}

	code, body, _ = admin.get("/settings/certificate.crt")
	blk, rest := pem.Decode([]byte(body))
	if code != 200 || blk == nil || blk.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("download: %d %q", code, body)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	served, _ := k.Get(nil)
	if !bytes.Equal(cert.Raw, served.Certificate[0]) {
		t.Error("the download is not the certificate the server presents")
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("the download contains a private key")
	}

	viewer := e.signedIn("val", RoleViewer)
	if c, _, _ := viewer.get("/settings/certificate.crt"); c == 200 {
		t.Error("a viewer can download the certificate from the admin-only settings")
	}
}

func TestMCPEndpointAddress(t *testing.T) {
	r := httptest.NewRequest("GET", "/settings", nil)
	r.Host = "example.internal:8443"
	if got := mcpEndpoint(r, Settings{}, true); got != "https://example.internal:8443/mcp" {
		t.Errorf("from the request: %s", got)
	}
	if got := mcpEndpoint(r, Settings{PublicURL: "https://easm.example.com/ "}, true); got != "https://easm.example.com/mcp" {
		t.Errorf("from the public URL: %s", got)
	}
	if got := mcpEndpoint(r, Settings{PublicURL: "javascript:alert(1)"}, false); got != "http://example.internal:8443/mcp" {
		t.Errorf("a public URL that is not http(s) is ignored: %s", got)
	}
}
