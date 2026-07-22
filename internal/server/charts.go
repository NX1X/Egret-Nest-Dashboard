package server

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// sparkBars renders a compact inline-SVG bar chart from values (chronological,
// oldest→newest). Bars use fill="currentColor", so the surrounding element's text
// colour (e.g. .viol / .new) tints them - no inline CSS and no JavaScript, so it
// stays within the CSP (default-src 'none'; style-src 'self'; script-src 'none').
// Inline SVG is document markup, not a fetched resource, so no CSP directive is
// needed for it. Returns "" when there is nothing to draw.
func sparkBars(values []int) template.HTML {
	const (
		h   = 28 // viewbox height
		bw  = 6  // bar width
		gap = 2  // gap between bars
		pad = 1
	)
	if len(values) == 0 {
		return ""
	}
	max := 0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	w := len(values)*(bw+gap) - gap + 2*pad
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="spark" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-hidden="true">`, w, h, w, h)
	for i, v := range values {
		bh := 1
		if max > 0 {
			bh = 1 + v*(h-2)/max
		}
		x := pad + i*(bw+gap)
		y := h - bh
		op := "0.2" // faint bar marks a run with a zero count
		if v > 0 {
			op = "1"
		}
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="currentColor" opacity="%s"/>`, x, y, bw, bh, op)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // numeric-only, server-generated SVG
}

// trend extracts an integer series from runs (which arrive newest-first) into
// chronological order (oldest→newest) via the provided field selector.
func trend(runs []store.RunSummary, field func(store.RunSummary) int) []int {
	out := make([]int, len(runs))
	for i, r := range runs {
		out[len(runs)-1-i] = field(r) // reverse newest-first → chronological
	}
	return out
}
