package watcher

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/aggregator"
	"github.com/arthurgray2k/goNetWatch/internal/dns"
	"github.com/arthurgray2k/goNetWatch/internal/history"
	"github.com/arthurgray2k/goNetWatch/internal/model"
	"github.com/arthurgray2k/goNetWatch/internal/output"
	"github.com/arthurgray2k/goNetWatch/internal/process"
)

// CollectorFunc is a function that collects current active connections.
type CollectorFunc func(includeListening bool) ([]*model.Connection, error)

// Watcher manages the live refresh loop for monitoring network activity.
type Watcher struct {
	collector   CollectorFunc
	procMapper  *process.Mapper
	resolver    *dns.Resolver
	store       *history.Store
	filterOpts  model.FilterOptions
	interval    time.Duration
	allFlag     bool
	remoteAgg   bool
	processAgg  bool
	resolveFlag bool
	noColorFlag bool
	prevConns   map[string]*model.Connection
	lastTime    time.Time
}

// Config holds configuration options for the live Watcher.
type Config struct {
	Collector   CollectorFunc
	ProcMapper  *process.Mapper
	Resolver    *dns.Resolver
	Store       *history.Store
	FilterOpts  model.FilterOptions
	Interval    time.Duration
	AllFlag     bool
	RemoteAgg   bool
	ProcessAgg  bool
	ResolveFlag bool
	NoColorFlag bool
}

// NewWatcher creates a new Watcher instance.
func NewWatcher(cfg Config) *Watcher {
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Second
	}
	return &Watcher{
		collector:   cfg.Collector,
		procMapper:  cfg.ProcMapper,
		resolver:    cfg.Resolver,
		store:       cfg.Store,
		filterOpts:  cfg.FilterOpts,
		interval:    cfg.Interval,
		allFlag:     cfg.AllFlag,
		remoteAgg:   cfg.RemoteAgg,
		processAgg:  cfg.ProcessAgg,
		resolveFlag: cfg.ResolveFlag,
		noColorFlag: cfg.NoColorFlag,
		prevConns:   make(map[string]*model.Connection),
	}
}

// Run executes the live monitoring loop until interrupted by SIGINT / SIGTERM or context cancellation.
func (w *Watcher) Run(ctx context.Context, out io.Writer) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Initial render
	if err := w.renderIteration(out); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sigChan:
			fmt.Fprintln(out, "\nExiting live network monitor.")
			return nil
		case <-ticker.C:
			if err := w.renderIteration(out); err != nil {
				return err
			}
		}
	}
}

func (w *Watcher) renderIteration(out io.Writer) error {
	conns, err := w.collector(w.allFlag)
	if err != nil {
		return err
	}

	// Correlate processes
	if w.procMapper != nil {
		_ = w.procMapper.Correlate(conns)
	}

	// Resolve DNS if enabled
	if w.resolveFlag && w.resolver != nil {
		w.resolver.ResolveConnections(conns)
	}

	// Calculate live rates based on previous iteration
	now := time.Now()
	if !w.lastTime.IsZero() {
		dt := now.Sub(w.lastTime).Seconds()
		if dt > 0 {
			for _, c := range conns {
				key := connKey(c)
				if prev, exists := w.prevConns[key]; exists {
					if c.RXBytes >= prev.RXBytes {
						c.RXRate = float64(c.RXBytes-prev.RXBytes) / dt
					}
					if c.TXBytes >= prev.TXBytes {
						c.TXRate = float64(c.TXBytes-prev.TXBytes) / dt
					}
				}
			}
		}
	}

	// Update previous map and timestamp
	newPrev := make(map[string]*model.Connection)
	for _, c := range conns {
		newPrev[connKey(c)] = c
	}
	w.prevConns = newPrev
	w.lastTime = now

	// Record snapshot in history store
	if w.store != nil {
		_ = w.store.Record(conns)
	}

	// Filter connections
	filtered := aggregator.FilterConnections(conns, w.filterOpts)

	// Clear terminal screen and move cursor to top-left
	if output.ShouldColorize(w.noColorFlag) {
		fmt.Fprint(out, "\033[H\033[2J")
	}

	headerTime := time.Now().Format("15:04:05")
	fmt.Fprintf(out, "goNetWatch — Live Monitor (refresh: %s, time: %s)\n\n", w.interval, headerTime)

	if w.remoteAgg {
		hosts := aggregator.AggregateByRemote(filtered)
		output.PrintRemoteAggregation(out, hosts, w.resolveFlag, w.noColorFlag)
		return nil
	}

	if w.processAgg {
		procs := aggregator.AggregateByProcess(filtered)
		output.PrintProcessAggregation(out, procs, w.noColorFlag)
		return nil
	}

	output.PrintConnections(out, filtered, w.resolveFlag, w.noColorFlag)
	return nil
}

func connKey(c *model.Connection) string {
	if c.Inode > 0 {
		return fmt.Sprintf("ino:%d", c.Inode)
	}
	return fmt.Sprintf("%s-%s-%s", c.Protocol, c.LocalEndpoint(), c.RemoteEndpoint(false))
}
