package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/aggregator"
	"github.com/arthurgray2k/goNetWatch/internal/dns"
	"github.com/arthurgray2k/goNetWatch/internal/history"
	"github.com/arthurgray2k/goNetWatch/internal/model"
	"github.com/arthurgray2k/goNetWatch/internal/netlink"
	"github.com/arthurgray2k/goNetWatch/internal/output"
	"github.com/arthurgray2k/goNetWatch/internal/process"
	"github.com/arthurgray2k/goNetWatch/internal/procnet"
	"github.com/arthurgray2k/goNetWatch/internal/watcher"
)

var version = "0.1.0"

func main() {
	var (
		watchFlag        bool
		intervalSec      int
		hoursFlag        int
		clearHistoryFlag bool
		remoteAggFlag    bool
		processAggFlag   bool
		pidFlag          int
		procFlag         string
		remoteFilter     string
		portFlag         int
		localFlag        bool
		externalFlag     bool
		allFlag          bool
		resolveFlag      bool
		jsonFlag         bool
		noColorFlag      bool
		versionFlag      bool
		helpFlag         bool
	)

	flag.BoolVar(&watchFlag, "watch", false, "Live monitoring mode (periodically refreshes terminal)")
	flag.IntVar(&intervalSec, "interval", 2, "Refresh interval in seconds for --watch mode")
	flag.IntVar(&hoursFlag, "hours", 0, "Show historical hourly summary over the last N hours")
	flag.BoolVar(&clearHistoryFlag, "clear-history", false, "Purge local historical activity records")
	flag.BoolVar(&remoteAggFlag, "remote", false, "Aggregate traffic and connections by remote host/IP")
	flag.BoolVar(&processAggFlag, "process", false, "Aggregate traffic and connections by process/PID")
	flag.IntVar(&pidFlag, "pid", 0, "Filter connections by Process ID (PID)")
	flag.StringVar(&procFlag, "proc", "", "Filter connections by process name")
	flag.StringVar(&remoteFilter, "host", "", "Filter connections by remote IP address or host")
	flag.IntVar(&portFlag, "port", 0, "Filter connections by local or remote port")
	flag.BoolVar(&localFlag, "local", false, "Show local network connections only")
	flag.BoolVar(&externalFlag, "external", false, "Show external/internet connections only")
	flag.BoolVar(&allFlag, "all", false, "Include listening and idle sockets")
	flag.BoolVar(&resolveFlag, "resolve", false, "Perform reverse DNS lookups on remote IPs")
	flag.BoolVar(&jsonFlag, "json", false, "Output results in JSON format")
	flag.BoolVar(&noColorFlag, "no-color", false, "Disable ANSI color formatting")
	flag.BoolVar(&versionFlag, "version", false, "Display version information")
	flag.BoolVar(&helpFlag, "help", false, "Show help message")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "goNetWatch - Local Network Traffic & Connection Monitor (v%s)\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch [flags] [filter]\n\n")
		fmt.Fprintf(os.Stderr, "Modes:\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch                 Display active connections by network scope\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --watch         Live monitoring mode (auto-refreshing table)\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --remote        Aggregate statistics by remote host/IP\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --process       Aggregate statistics by process/PID\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --hours <N>     Historical hourly activity summary (e.g. --hours 24)\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --clear-history Purge local recorded history\n\n")
		fmt.Fprintf(os.Stderr, "Filters:\n")
		fmt.Fprintf(os.Stderr, "  --pid <PID>                Filter by Process ID\n")
		fmt.Fprintf(os.Stderr, "  --proc <name>              Filter by process name (e.g. chrome, code)\n")
		fmt.Fprintf(os.Stderr, "  --host <ip/host>           Filter by remote IP or hostname\n")
		fmt.Fprintf(os.Stderr, "  --port <port>              Filter by port number (local or remote)\n")
		fmt.Fprintf(os.Stderr, "  --local                    Show local network connections only\n")
		fmt.Fprintf(os.Stderr, "  --external                 Show external/internet connections only\n")
		fmt.Fprintf(os.Stderr, "  --all                      Include listening and idle sockets\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --interval <sec>           Refresh interval for --watch mode (default: 2s)\n")
		fmt.Fprintf(os.Stderr, "  --resolve                  Perform reverse DNS resolution\n")
		fmt.Fprintf(os.Stderr, "  --json                     Output structured JSON\n")
		fmt.Fprintf(os.Stderr, "  --no-color                 Disable color formatting\n")
		fmt.Fprintf(os.Stderr, "  --version                  Show version information\n")
		fmt.Fprintf(os.Stderr, "  --help                     Show this help message\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --watch --interval 5\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --remote\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --process\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --hours 24\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch 443\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch chrome\n")
		fmt.Fprintf(os.Stderr, "  goNetWatch --resolve --json\n")
	}

	flag.Parse()

	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if versionFlag {
		fmt.Printf("goNetWatch v%s\n", version)
		os.Exit(0)
	}

	// Initialize history store
	histStore, err := history.NewStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to initialize history store: %v\n", err)
	}

	// Handle --clear-history
	if clearHistoryFlag {
		if histStore != nil {
			if err := histStore.Clear(); err != nil {
				fmt.Fprintf(os.Stderr, "Error clearing history: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Local history records cleared successfully.")
		}
		return
	}

	// Handle --hours <N>
	if hoursFlag > 0 {
		if histStore == nil {
			fmt.Fprintf(os.Stderr, "Error: history store unavailable\n")
			os.Exit(1)
		}
		summary, err := histStore.GetSummary(hoursFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error querying history: %v\n", err)
			os.Exit(1)
		}
		if jsonFlag {
			if err := output.PrintJSON(os.Stdout, summary); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
				os.Exit(1)
			}
			return
		}
		output.PrintHistory(os.Stdout, summary, noColorFlag)
		return
	}

	filterOpts := model.FilterOptions{
		PID:          pidFlag,
		ProcessName:  procFlag,
		RemoteTarget: remoteFilter,
		Port:         portFlag,
		LocalOnly:    localFlag,
		ExternalOnly: externalFlag,
	}

	// Support positional argument (e.g. "goNetWatch 443", "goNetWatch chrome")
	args := flag.Args()
	if len(args) > 0 {
		arg := args[0]
		if port, err := strconv.Atoi(arg); err == nil && port > 0 && port <= 65535 {
			filterOpts.Port = port
		} else {
			filterOpts.ProcessName = arg
		}
	}

	procMapper := process.NewMapper("/proc")
	var resolver *dns.Resolver
	if resolveFlag {
		resolver = dns.NewResolver(true, 800*time.Millisecond)
	}

	// Live Watch Mode
	if watchFlag {
		w := watcher.NewWatcher(watcher.Config{
			Collector:   collectConnections,
			ProcMapper:  procMapper,
			Resolver:    resolver,
			Store:       histStore,
			FilterOpts:  filterOpts,
			Interval:    time.Duration(intervalSec) * time.Second,
			AllFlag:     allFlag,
			RemoteAgg:   remoteAggFlag,
			ProcessAgg:  processAggFlag,
			ResolveFlag: resolveFlag,
			NoColorFlag: noColorFlag,
		})

		ctx := context.Background()
		if err := w.Run(ctx, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Watch mode error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	conns, err := collectConnections(allFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting network connections: %v\n", err)
		os.Exit(1)
	}

	// Correlate with processes
	_ = procMapper.Correlate(conns)

	// Resolve DNS if requested
	if resolveFlag && resolver != nil {
		resolver.ResolveConnections(conns)
	}

	// Record snapshot in history
	if histStore != nil {
		_ = histStore.Record(conns)
	}

	// Apply filtering
	filtered := aggregator.FilterConnections(conns, filterOpts)

	if jsonFlag {
		if remoteAggFlag {
			hosts := aggregator.AggregateByRemote(filtered)
			if err := output.PrintJSON(os.Stdout, hosts); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
				os.Exit(1)
			}
			return
		}

		if processAggFlag {
			procs := aggregator.AggregateByProcess(filtered)
			if err := output.PrintJSON(os.Stdout, procs); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
				os.Exit(1)
			}
			return
		}

		totalConns, totalRX, totalTX := aggregator.CalculateTotals(filtered)
		result := struct {
			Connections      []*model.Connection `json:"connections"`
			TotalConnections int                 `json:"total_connections"`
			TotalRXBytes     uint64              `json:"total_rx_bytes"`
			TotalTXBytes     uint64              `json:"total_tx_bytes"`
		}{
			Connections:      filtered,
			TotalConnections: totalConns,
			TotalRXBytes:     totalRX,
			TotalTXBytes:     totalTX,
		}

		if err := output.PrintJSON(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Render text output
	if remoteAggFlag {
		hosts := aggregator.AggregateByRemote(filtered)
		output.PrintRemoteAggregation(os.Stdout, hosts, resolveFlag, noColorFlag)
		return
	}

	if processAggFlag {
		procs := aggregator.AggregateByProcess(filtered)
		output.PrintProcessAggregation(os.Stdout, procs, noColorFlag)
		return
	}

	output.PrintConnections(os.Stdout, filtered, resolveFlag, noColorFlag)
}

func collectConnections(includeListening bool) ([]*model.Connection, error) {
	var conns []*model.Connection
	seenInodes := make(map[uint64]bool)

	// 1. Try Netlink sock_diag for rich TCP stats
	nlScanner := netlink.NewScanner()
	nlConns, err := nlScanner.ScanSockets(includeListening)
	if err == nil {
		for _, c := range nlConns {
			if c.Inode > 0 {
				seenInodes[c.Inode] = true
			}
			conns = append(conns, c)
		}
	}

	// 2. Scan /proc/net for UDP and any TCP sockets missed
	procScanner := procnet.NewScanner("/proc")
	procConns, err := procScanner.ScanConnections(includeListening)
	if err == nil {
		for _, c := range procConns {
			if c.Inode > 0 && seenInodes[c.Inode] {
				continue
			}
			conns = append(conns, c)
		}
	}

	return conns, nil
}
