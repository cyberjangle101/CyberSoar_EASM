package main

import (
	"os"
	"path/filepath"
	"testing"
)

// After an update the agent restarts with a console window only when its key-file passphrase has
// to be typed in. Otherwise it starts with none, so no window can be left open (v1.9.17 left the
// window of an update restart open on Windows).
func TestRestartNeedsWindowOnlyForAPassphrasePrompt(t *testing.T) {
	t.Setenv("EASM_KEY_PASSPHRASE", "")
	t.Setenv("EASM_KEY_PASSPHRASE_FILE", "")
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	scrypt := write("pass.key", wrappedMagic+"AAAA\n")
	cases := map[string]struct {
		path string
		want bool
	}{
		"passphrase-protected key": {scrypt, true},
		"Windows-account key":      {write("dpapi.key", dpapiMagic+"AAAA\n"), false},
		"unprotected key":          {write("plain.key", "c2VjcmV0\n"), false},
		"unreadable key":           {filepath.Join(dir, "missing.key"), true}, // cannot tell: keep the prompt possible
	}
	for name, c := range cases {
		if got := restartNeedsWindow(c.path); got != c.want {
			t.Errorf("%s: restartNeedsWindow = %v, want %v", name, got, c.want)
		}
	}
	t.Setenv("EASM_KEY_PASSPHRASE", "from-the-environment")
	if restartNeedsWindow(scrypt) {
		t.Error("with the passphrase in the environment nothing has to be typed, so no window is needed")
	}
}
