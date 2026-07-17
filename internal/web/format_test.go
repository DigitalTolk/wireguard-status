package web

import (
	"testing"
	"time"
)

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		0:                      "0 B",
		512:                    "512 B",
		1024:                   "1.0 KiB",
		1536:                   "1.5 KiB",
		5 * 1024 * 1024:        "5.0 MiB",
		3 * 1024 * 1024 * 1024: "3.0 GiB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanAgo(t *testing.T) {
	if got := humanAgo(time.Time{}); got != "never" {
		t.Errorf("humanAgo(zero) = %q, want never", got)
	}
	if got := humanAgo(time.Now().Add(-90 * time.Second)); got == "never" || got == "" {
		t.Errorf("humanAgo(recent) = %q, want a duration", got)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		0:                           "0s",
		-5 * time.Second:            "0s",
		30 * time.Second:            "30s",
		90 * time.Second:            "1m 30s",
		2*time.Hour + 5*time.Minute: "2h 5m",
		49 * time.Hour:              "2d 1h",
	}
	for in, want := range cases {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestStateBadge(t *testing.T) {
	cases := map[string]string{"up": "up", "never": "never", "down": "down", "weird": "down"}
	for in, want := range cases {
		if got := stateBadge(in); got != want {
			t.Errorf("stateBadge(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTemplateFuncs(t *testing.T) {
	join := tmplFuncs["join"].(func([]string) string)
	if got := join([]string{"a", "b"}); got != "a, b" {
		t.Errorf("join = %q, want %q", got, "a, b")
	}

	localtime := tmplFuncs["localtime"].(func(time.Time) string)
	if got := localtime(time.Time{}); got != "—" {
		t.Errorf("localtime(zero) = %q, want —", got)
	}
	ts := time.Date(2026, 7, 17, 15, 4, 5, 0, time.UTC)
	if got := localtime(ts); got != "15:04:05" {
		t.Errorf("localtime = %q, want 15:04:05", got)
	}
}
