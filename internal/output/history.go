package output

import (
	"fmt"
	"io"

	"github.com/arthurgray2k/goNetWatch/internal/history"
)

// PrintHistory renders the historical hourly network activity report.
func PrintHistory(w io.Writer, summary *history.HistorySummary, noColor bool) {
	useColor := ShouldColorize(noColor)
	bold := "\033[1m"
	cyan := "\033[36m"
	green := "\033[32m"
	yellow := "\033[33m"
	dim := "\033[2m"
	reset := "\033[0m"

	if !useColor {
		bold = ""
		cyan = ""
		green = ""
		yellow = ""
		dim = ""
		reset = ""
	}

	fmt.Fprintf(w, "%sNETWORK ACTIVITY — LAST %d HOURS%s\n\n", bold, summary.Hours, reset)
	fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(w, "%-10s %-14s %14s %14s\n", "TIME", "CONNECTIONS", "RX", "TX")

	for _, r := range summary.Reports {
		fmt.Fprintf(w, "%-10s %-14d %14s %14s\n",
			r.HourLabel,
			r.Connections,
			FormatBytes(r.RXBytes),
			FormatBytes(r.TXBytes),
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sSUMMARY%s\n", bold, reset)
	fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(w, "  Average connections/hour: %s%.1f%s\n", yellow, summary.AvgConnectionsHour, reset)
	fmt.Fprintf(w, "  Average RX/hour:          %s%s%s\n", green, FormatBytes(summary.AvgRXHour), reset)
	fmt.Fprintf(w, "  Average TX/hour:          %s%s%s\n", cyan, FormatBytes(summary.AvgTXHour), reset)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Total RX:                 %s%s%s\n", green, FormatBytes(summary.TotalRX), reset)
	fmt.Fprintf(w, "  Total TX:                 %s%s%s\n", cyan, FormatBytes(summary.TotalTX), reset)
	if summary.TotalSnapshots == 0 {
		fmt.Fprintf(w, "\n  %s(No historical snapshots recorded yet for this period)%s\n", dim, reset)
	}
}
