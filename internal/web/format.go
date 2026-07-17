package web

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

var tmplFuncs = template.FuncMap{
	"bytes":    humanBytes,
	"ago":      humanAgo,
	"duration": humanDuration,
	"join":     func(s []string) string { return strings.Join(s, ", ") },
	"badge":    stateBadge,
	"localtime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Format("15:04:05")
	},
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return humanDuration(time.Since(t)) + " ago"
}

func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

// stateBadge maps a peer state to a CSS class suffix.
func stateBadge(state string) string {
	switch state {
	case "up":
		return "up"
	case "never":
		return "never"
	default:
		return "down"
	}
}
