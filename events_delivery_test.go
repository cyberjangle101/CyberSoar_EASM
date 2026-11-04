package main

import (
	"strings"
	"testing"
)

// eventsAfterBaseline scans example.test once (the silent baseline), adds a new host, and scans
// again, so the second scan raises events that are due for an alert.
func eventsAfterBaseline(t *testing.T, e *webEnv) {
	t.Helper()
	e.seedExample()
	tg := e.addTarget("example.test", "")
	if tg = e.scan(tg.ID); !tg.Baselined() {
		t.Fatal("the first scan should set the baseline")
	}
	e.src.addAnubis("surprise.example.test")
	e.dns.add(t, "surprise.example.test. 60 IN A 203.0.113.50")
	e.dns.addIP(t, "203.0.113.50", 64500, "203.0.113.0/24", "EXAMPLE-NET")
	e.scan(tg.ID)
}

// The Events page says "sent" only when an alert email really went out. With email not set up,
// the alert goes to the log and the page says so (before 1.9.18 it said "sent").
func TestEventsPageSaysWhetherEmailWasSent(t *testing.T) {
	t.Run("email not set up", func(t *testing.T) {
		e := newWebEnv(t)
		st, _ := e.store.LoadSettings()
		st.SMTPEnabled = false
		e.saveSettings(st)
		eventsAfterBaseline(t, e)
		if n := e.smtp.count(); n != 0 {
			t.Fatalf("%d emails sent with email switched off", n)
		}
		admin := e.signedIn("boss", RoleAdmin)
		_, body, _ := admin.get("/events")
		if !strings.Contains(body, "surprise.example.test") {
			t.Fatal("the new host's event is not listed")
		}
		if strings.Contains(body, `badge good">sent<`) || !strings.Contains(body, `">not sent<`) {
			t.Error("with email not set up, events must say not sent, never sent")
		}
		if !strings.Contains(body, "Email is not set up") || !strings.Contains(body, `href="/settings#smtp"`) {
			t.Error("the page should say email is not set up and link to its settings")
		}
		// Nothing is left queued either: the alert was handled, by writing it to the log.
		var queued int
		_ = e.store.db.QueryRow(`SELECT COUNT(*) FROM events WHERE notified=0`).Scan(&queued)
		if queued != 0 {
			t.Errorf("%d events still queued", queued)
		}
	})

	t.Run("email set up", func(t *testing.T) {
		e := newWebEnv(t) // the harness points email at a fake SMTP server
		eventsAfterBaseline(t, e)
		if e.smtp.count() == 0 {
			t.Fatal("no alert email was sent")
		}
		admin := e.signedIn("boss", RoleAdmin)
		_, body, _ := admin.get("/events")
		if !strings.Contains(body, `badge good">sent<`) || strings.Contains(body, `">not sent<`) || strings.Contains(body, "Email is not set up") {
			t.Error("events whose alert email went out should say sent")
		}
	})

	t.Run("muted and older events", func(t *testing.T) {
		e := newWebEnv(t)
		e.seedExample()
		e.addTarget("example.test", "")
		ins := `INSERT INTO events(ts,root,kind,severity,host,detail,notified,baseline,muted) VALUES(?,?,?,?,?,?,1,0,?)`
		if _, err := e.store.db.Exec(ins, nowUTC(), "example.test", "subdomain", "low", "old.example.test", "written by 1.9.17", 0); err != nil {
			t.Fatal(err) // no delivery column given: the default for rows from before 1.9.18
		}
		tx, err := e.store.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.AddEvent(Event{TS: nowUTC(), Root: "example.test", Kind: "finding-resolved", Severity: "info", Host: "quiet.example.test", Detail: "recorded only", NoAlert: true}, false); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		admin := e.signedIn("boss", RoleAdmin)
		_, body, _ := admin.get("/events")
		if !strings.Contains(body, `">not recorded<`) || !strings.Contains(body, `">not alerted<`) || strings.Contains(body, `badge good">sent<`) {
			t.Error("an older event should say not recorded, and a muted one not alerted")
		}
	})
}
