package server

import (
	"strings"
	"testing"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

func TestSparkBars(t *testing.T) {
	// Empty → nothing to draw.
	if got := sparkBars(nil); got != "" {
		t.Errorf("empty sparkBars = %q, want \"\"", got)
	}
	// One bar per value; valid <svg>…</svg> with fill=currentColor (CSP-safe, no JS).
	svg := string(sparkBars([]int{0, 2, 5, 1}))
	if !strings.HasPrefix(svg, "<svg") || !strings.HasSuffix(svg, "</svg>") {
		t.Fatalf("not an svg element: %q", svg)
	}
	if n := strings.Count(svg, "<rect"); n != 4 {
		t.Errorf("rect count = %d, want 4", n)
	}
	if !strings.Contains(svg, `fill="currentColor"`) {
		t.Error("bars must use fill=currentColor so .new/.viol tints them")
	}
	if strings.Contains(svg, "<script") || strings.Contains(svg, "style=") {
		t.Error("sparkline must not contain script or inline style (CSP)")
	}
	// All zeros still renders bars (faint), doesn't divide by zero.
	if z := string(sparkBars([]int{0, 0, 0})); strings.Count(z, "<rect") != 3 {
		t.Errorf("all-zero rects = %d, want 3", strings.Count(z, "<rect"))
	}
}

func TestTrendReversesToChronological(t *testing.T) {
	// RunsForRepo returns newest-first; the trend must be oldest→newest.
	runs := []store.RunSummary{
		{NumNewEndpoints: 3}, // newest
		{NumNewEndpoints: 2},
		{NumNewEndpoints: 1}, // oldest
	}
	got := trend(runs, func(r store.RunSummary) int { return r.NumNewEndpoints })
	want := []int{1, 2, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trend = %v, want %v (chronological)", got, want)
		}
	}
}
