package main

import (
	"context"
	"testing"
	"time"
)

// The scheduler loop itself (not a direct runDue call) starts each domain's scan on its own when the
// domain's next scan time passes: nobody presses Scan now and nothing wakes the engine. A domain whose
// time has not come is left alone, a paused one is never scanned, and every scan schedules the next.
func TestSchedulerScansDomainsAutomaticallyWhenDue(t *testing.T) {
	h := newHarness(t)
	h.seedExample()
	h.eng.tickEvery = 50 * time.Millisecond

	scans := func() int {
		recs, err := h.store.ListScans("example.test", 100)
		if err != nil {
			t.Fatal(err)
		}
		return len(recs)
	}
	setNext := func(id int64, at time.Time) {
		if _, err := h.store.db.Exec(`UPDATE targets SET next_scan=? WHERE id=?`, at.UTC().Format(time.RFC3339), id); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.eng.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// A new domain is due at once: the first (baseline) scan starts without a wake-up.
	tg := h.addTarget("example.test", "")
	waitFor(t, "the first scan", 10*time.Second, func() bool { return scans() == 1 })
	got, _ := h.store.GetTarget(tg.ID)
	next, _ := time.Parse(time.RFC3339, got.NextScan)
	if d := time.Until(next); got.LastStatus != "ok" || d < 5*time.Hour || d > 7*time.Hour {
		t.Fatalf("after the first scan: status %q, next scan in %v (want ~6h: the default interval plus jitter)", got.LastStatus, d)
	}

	// Not yet due: the loop keeps ticking and leaves it alone.
	setNext(tg.ID, time.Now().Add(time.Hour))
	time.Sleep(10 * h.eng.tickEvery)
	if n := scans(); n != 1 {
		t.Fatalf("a domain that is not due was scanned: %d scans", n)
	}

	// Its interval elapses: the next scan starts by itself and schedules the one after.
	setNext(tg.ID, time.Now().Add(-time.Second))
	waitFor(t, "the scheduled scan", 10*time.Second, func() bool { return scans() == 2 })
	waitFor(t, "the next scan time", 5*time.Second, func() bool {
		g, _ := h.store.GetTarget(tg.ID)
		n, _ := time.Parse(time.RFC3339, g.NextScan)
		return g.LastStatus == "ok" && time.Until(n) > 5*time.Hour
	})

	// Paused: a passed scan time never starts a scan.
	if err := h.store.SetTargetEnabled(tg.ID, false); err != nil {
		t.Fatal(err)
	}
	setNext(tg.ID, time.Now().Add(-time.Second))
	time.Sleep(10 * h.eng.tickEvery)
	if n := scans(); n != 2 {
		t.Fatalf("a paused domain was scanned: %d scans", n)
	}
}
