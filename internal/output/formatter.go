package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arthurgray2k/goNetWatch/internal/aggregator"
	"github.com/arthurgray2k/goNetWatch/internal/model"
)

// FormatBytes converts a byte count into human-readable binary prefix units.
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatRate converts bytes per second into a human-readable rate string.
func FormatRate(bps float64) string {
	if bps < 1024 {
		return fmt.Sprintf("%.0f B/s", bps)
	}
	if bps < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", bps/1024)
	}
	if bps < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB/s", bps/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB/s", bps/(1024*1024*1024))
}

// PrintJSON outputs any data structure as indented JSON.
func PrintJSON(w io.Writer, data any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// ShouldColorize returns true if ANSI colors should be emitted.
func ShouldColorize(noColorFlag bool) bool {
	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// PrintConnections renders active connections grouped by scope.
func PrintConnections(w io.Writer, conns []*model.Connection, preferHost bool, noColor bool) {
	if len(conns) == 0 {
		fmt.Fprintln(w, "No active network connections found.")
		return
	}

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

	localConns, extConns := aggregator.SeparateByScope(conns)
	totalConns, totalRX, totalTX := aggregator.CalculateTotals(conns)

	fmt.Fprintf(w, "%sNETWORK ACTIVITY%s\n\n", bold, reset)

	if len(extConns) > 0 {
		fmt.Fprintf(w, "%s%sEXTERNAL / INTERNET (%d connections)%s\n", bold, cyan, len(extConns), reset)
		fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────────────────────────────────%s\n", dim, reset)
		fmt.Fprintf(w, "%-30s %-16s %-8s %-14s %10s %10s\n", "REMOTE", "PROCESS", "PID", "STATE", "RX", "TX")

		for _, c := range extConns {
			remStr := c.RemoteEndpoint(preferHost)
			pidStr := "-"
			if c.PID > 0 {
				pidStr = fmt.Sprintf("%d", c.PID)
			}
			rxStr := FormatBytes(c.RXBytes)
			txStr := FormatBytes(c.TXBytes)

			fmt.Fprintf(w, "%-30s %-16s %-8s %-14s %10s %10s\n",
				truncate(remStr, 30),
				truncate(c.ProcessName, 16),
				pidStr,
				c.State,
				rxStr,
				txStr,
			)
		}
		fmt.Fprintln(w)
	}

	if len(localConns) > 0 {
		fmt.Fprintf(w, "%s%sLOCAL NETWORK (%d connections)%s\n", bold, green, len(localConns), reset)
		fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────────────────────────────────%s\n", dim, reset)
		fmt.Fprintf(w, "%-30s %-16s %-8s %-14s %10s %10s\n", "REMOTE", "PROCESS", "PID", "STATE", "RX", "TX")

		for _, c := range localConns {
			remStr := c.RemoteEndpoint(preferHost)
			pidStr := "-"
			if c.PID > 0 {
				pidStr = fmt.Sprintf("%d", c.PID)
			}
			rxStr := FormatBytes(c.RXBytes)
			txStr := FormatBytes(c.TXBytes)

			fmt.Fprintf(w, "%-30s %-16s %-8s %-14s %10s %10s\n",
				truncate(remStr, 30),
				truncate(c.ProcessName, 16),
				pidStr,
				c.State,
				rxStr,
				txStr,
			)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%sSUMMARY%s\n", bold, reset)
	fmt.Fprintf(w, "%s────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(w, "  Total Connections: %s%d%s (External: %d, Local: %d)\n", yellow, totalConns, reset, len(extConns), len(localConns))
	fmt.Fprintf(w, "  Total RX:          %s%s%s\n", green, FormatBytes(totalRX), reset)
	fmt.Fprintf(w, "  Total TX:          %s%s%s\n", cyan, FormatBytes(totalTX), reset)
}

// PrintRemoteAggregation renders grouped host statistics.
func PrintRemoteAggregation(w io.Writer, hosts []*model.HostSummary, preferHost bool, noColor bool) {
	if len(hosts) == 0 {
		fmt.Fprintln(w, "No matching remote hosts found.")
		return
	}

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

	var totalConns int
	var totalRX, totalTX uint64
	for _, h := range hosts {
		totalConns += h.Connections
		totalRX += h.RXBytes
		totalTX += h.TXBytes
	}

	fmt.Fprintf(w, "%sNETWORK ACTIVITY — REMOTE HOSTS%s\n\n", bold, reset)
	fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(w, "%-26s %-15s %-7s %-20s %10s %10s\n", "REMOTE HOST", "SCOPE", "CONNS", "PROCESSES", "RX", "TX")

	for _, h := range hosts {
		hostStr := h.RemoteIP.String()
		if preferHost && h.RemoteHost != "" {
			hostStr = h.RemoteHost
		}

		procs := strings.Join(h.Processes, ", ")
		if procs == "" {
			procs = "-"
		}

		scopeColor := cyan
		if h.Scope == model.ScopeLocal {
			scopeColor = green
		}

		fmt.Fprintf(w, "%-26s %s%-15s%s %-7d %-20s %10s %10s\n",
			truncate(hostStr, 26),
			scopeColor,
			h.Scope,
			reset,
			h.Connections,
			truncate(procs, 20),
			FormatBytes(h.RXBytes),
			FormatBytes(h.TXBytes),
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sSUMMARY%s\n", bold, reset)
	fmt.Fprintf(w, "%s────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(w, "  Total Hosts:       %s%d%s\n", yellow, len(hosts), reset)
	fmt.Fprintf(w, "  Total Connections: %d\n", totalConns)
	fmt.Fprintf(w, "  Total RX:          %s%s%s\n", green, FormatBytes(totalRX), reset)
	fmt.Fprintf(w, "  Total TX:          %s%s%s\n", cyan, FormatBytes(totalTX), reset)
}

// PrintProcessAggregation renders grouped process statistics.
func PrintProcessAggregation(w io.Writer, procs []*model.ProcessSummary, noColor bool) {
	if len(procs) == 0 {
		fmt.Fprintln(w, "No matching processes found.")
		return
	}

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

	var totalConns int
	var totalRX, totalTX uint64
	for _, p := range procs {
		totalConns += p.Connections
		totalRX += p.RXBytes
		totalTX += p.TXBytes
	}

	fmt.Fprintf(w, "%sNETWORK ACTIVITY — PROCESSES%s\n\n", bold, reset)
	fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(w, "%-18s %-8s %-10s %-7s %-24s %10s %10s\n", "PROCESS", "PID", "USER", "CONNS", "REMOTE HOSTS", "RX", "TX")

	for _, p := range procs {
		pidStr := "-"
		if p.PID > 0 {
			pidStr = fmt.Sprintf("%d", p.PID)
		}
		userStr := p.User
		if userStr == "" {
			userStr = "-"
		}
		remotes := strings.Join(p.RemoteHosts, ", ")
		if remotes == "" {
			remotes = "-"
		}

		fmt.Fprintf(w, "%-18s %-8s %-10s %-7d %-24s %10s %10s\n",
			truncate(p.ProcessName, 18),
			pidStr,
			truncate(userStr, 10),
			p.Connections,
			truncate(remotes, 24),
			FormatBytes(p.RXBytes),
			FormatBytes(p.TXBytes),
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sSUMMARY%s\n", bold, reset)
	fmt.Fprintf(w, "%s────────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(w, "  Total Processes:   %s%d%s\n", yellow, len(procs), reset)
	fmt.Fprintf(w, "  Total Connections: %d\n", totalConns)
	fmt.Fprintf(w, "  Total RX:          %s%s%s\n", green, FormatBytes(totalRX), reset)
	fmt.Fprintf(w, "  Total TX:          %s%s%s\n", cyan, FormatBytes(totalTX), reset)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
