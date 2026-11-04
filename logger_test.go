package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Log values such as usernames and domains come from users. Both log formats must escape
// line breaks in them, so a value can never start a forged log line (CodeQL go/log-injection).
func TestLogValuesCannotForgeLines(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "agent.log")
			log, closeLog, err := SetupLogger(LoggingCfg{Level: "info", Format: format, File: file})
			if err != nil {
				t.Fatal(err)
			}
			log.Info("user created", "user", "eve\nlevel=ERROR msg=\"forged\"\r\n{\"msg\":\"forged\"}")
			closeLog()
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) != 1 || strings.Contains(string(b), "\r") {
				t.Fatalf("one log entry became %d lines:\n%s", len(lines), b)
			}
		})
	}
}
