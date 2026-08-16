package watcher

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/dns"
	"github.com/arthurgray2k/goNetWatch/internal/history"
	"github.com/arthurgray2k/goNetWatch/internal/model"
	"github.com/arthurgray2k/goNetWatch/internal/process"
)

func TestWatcher_RenderIterationAndRate(t *testing.T) {
	iter := 0
	mockCollector := func(includeListening bool) ([]*model.Connection, error) {
		iter++
		rx := uint64(1000)
		tx := uint64(500)
		if iter > 1 {
			rx = 3000
			tx = 1500
		}
		return []*model.Connection{
			{
				Protocol:    "TCP",
				LocalIP:     net.ParseIP("192.168.1.50"),
				LocalPort:   54321,
				RemoteIP:    net.ParseIP("142.250.190.46"),
				RemotePort:  443,
				State:       "ESTABLISHED",
				Scope:       model.ScopeExternal,
				Inode:       12345,
				ProcessName: "chrome",
				PID:         1000,
				RXBytes:     rx,
				TXBytes:     tx,
			},
		}, nil
	}

	tmpDir := t.TempDir()
	store, _ := history.NewStore(filepath.Join(tmpDir, "history.json"))
	procMapper := process.NewMapper(tmpDir)
	resolver := dns.NewResolver(false, 0)

	w := NewWatcher(Config{
		Collector:   mockCollector,
		ProcMapper:  procMapper,
		Resolver:    resolver,
		Store:       store,
		Interval:    10 * time.Millisecond,
		NoColorFlag: true,
	})

	buf := new(bytes.Buffer)
	// First iteration
	if err := w.renderIteration(buf); err != nil {
		t.Fatalf("first render failed: %v", err)
	}

	if !strings.Contains(buf.String(), "chrome") {
		t.Errorf("expected chrome in output: %s", buf.String())
	}

	// Second iteration (should compute delta rates)
	time.Sleep(10 * time.Millisecond)
	buf.Reset()
	if err := w.renderIteration(buf); err != nil {
		t.Fatalf("second render failed: %v", err)
	}

	if !strings.Contains(buf.String(), "chrome") {
		t.Errorf("expected chrome in second render: %s", buf.String())
	}

	// Test with RemoteAgg and ProcessAgg
	wRemote := NewWatcher(Config{
		Collector:   mockCollector,
		RemoteAgg:   true,
		NoColorFlag: true,
	})
	buf.Reset()
	if err := wRemote.renderIteration(buf); err != nil {
		t.Fatalf("remote agg render failed: %v", err)
	}
	if !strings.Contains(buf.String(), "REMOTE HOSTS") {
		t.Errorf("expected REMOTE HOSTS header in output: %s", buf.String())
	}

	wProc := NewWatcher(Config{
		Collector:   mockCollector,
		ProcessAgg:  true,
		NoColorFlag: true,
	})
	buf.Reset()
	if err := wProc.renderIteration(buf); err != nil {
		t.Fatalf("proc agg render failed: %v", err)
	}
	if !strings.Contains(buf.String(), "PROCESSES") {
		t.Errorf("expected PROCESSES header in output: %s", buf.String())
	}
}

func TestWatcher_RunContextCancel(t *testing.T) {
	mockCollector := func(includeListening bool) ([]*model.Connection, error) {
		return []*model.Connection{}, nil
	}

	w := NewWatcher(Config{
		Collector:   mockCollector,
		Interval:    20 * time.Millisecond,
		NoColorFlag: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	buf := new(bytes.Buffer)
	err := w.Run(ctx, buf)
	if err != nil {
		t.Fatalf("Watcher.Run failed: %v", err)
	}
}
