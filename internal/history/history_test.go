package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

func TestStore_RecordAndSummary(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "history.json")

	store, err := NewStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	conns := []*model.Connection{
		{RXBytes: 1000, TXBytes: 500},
		{RXBytes: 2000, TXBytes: 1000},
	}

	if err := store.Record(conns); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	summary, err := store.GetSummary(24)
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	if summary.TotalSnapshots != 1 {
		t.Errorf("expected 1 snapshot, got %d", summary.TotalSnapshots)
	}
	if summary.TotalRX != 3000 {
		t.Errorf("expected TotalRX 3000, got %d", summary.TotalRX)
	}
	if summary.TotalTX != 1500 {
		t.Errorf("expected TotalTX 1500, got %d", summary.TotalTX)
	}
	if len(summary.Reports) != 24 {
		t.Errorf("expected 24 hourly reports, got %d", len(summary.Reports))
	}

	// Test clear
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	summaryAfter, _ := store.GetSummary(24)
	if summaryAfter.TotalSnapshots != 0 {
		t.Errorf("expected 0 snapshots after clear, got %d", summaryAfter.TotalSnapshots)
	}
}

func TestStore_PruneOld(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "history.json")

	store, err := NewStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Save an old snapshot (35 days ago)
	oldSnap := Snapshot{
		Timestamp:   time.Now().UTC().Add(-35 * 24 * time.Hour),
		Connections: 5,
		RXBytes:     100,
		TXBytes:     50,
	}
	_ = store.saveSnapshots([]Snapshot{oldSnap})

	// Record a new snapshot
	_ = store.Record([]*model.Connection{{RXBytes: 500, TXBytes: 200}})

	snapshots, _ := store.loadSnapshots()
	if len(snapshots) != 1 {
		t.Errorf("expected old snapshot to be pruned, got %d snapshots", len(snapshots))
	}
}
