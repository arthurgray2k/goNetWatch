package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

// Snapshot represents a single point-in-time network activity record.
type Snapshot struct {
	Timestamp   time.Time `json:"timestamp"`
	Connections int       `json:"connections"`
	RXBytes     uint64    `json:"rx_bytes"`
	TXBytes     uint64    `json:"tx_bytes"`
}

// HourlyReport aggregates statistics across an hourly bucket.
type HourlyReport struct {
	Hour        time.Time `json:"hour"`
	HourLabel   string    `json:"hour_label"`
	Connections int       `json:"connections"`
	RXBytes     uint64    `json:"rx_bytes"`
	TXBytes     uint64    `json:"tx_bytes"`
}

// HistorySummary provides averages and totals over a historical window.
type HistorySummary struct {
	Hours              int            `json:"hours"`
	Reports            []HourlyReport `json:"hourly_activity"`
	AvgConnectionsHour float64        `json:"avg_connections_hour"`
	AvgRXHour          uint64         `json:"avg_rx_hour"`
	AvgTXHour          uint64         `json:"avg_tx_hour"`
	TotalRX            uint64         `json:"total_rx"`
	TotalTX            uint64         `json:"total_tx"`
	TotalSnapshots     int            `json:"total_snapshots"`
}

// Store manages persistent history recording and queries.
type Store struct {
	filePath string
	mu       sync.Mutex
}

// NewStore creates a Store targeting the specified file (or default user data dir).
func NewStore(customPath string) (*Store, error) {
	if customPath != "" {
		if err := os.MkdirAll(filepath.Dir(customPath), 0755); err != nil {
			return nil, err
		}
		return &Store{filePath: customPath}, nil
	}

	dataDir := os.Getenv("GONETWATCH_DATA_DIR")
	if dataDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = os.TempDir()
		}
		dataDir = filepath.Join(homeDir, ".local", "share", "goNetWatch")
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}

	return &Store{filePath: filepath.Join(dataDir, "history.json")}, nil
}

// Record saves a snapshot of current network activity.
func (s *Store) Record(conns []*model.Connection) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var totalRX, totalTX uint64
	for _, c := range conns {
		totalRX += c.RXBytes
		totalTX += c.TXBytes
	}

	newSnap := Snapshot{
		Timestamp:   time.Now().UTC(),
		Connections: len(conns),
		RXBytes:     totalRX,
		TXBytes:     totalTX,
	}

	snapshots, _ := s.loadSnapshots()

	// Append and prune entries older than 30 days
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	var filtered []Snapshot
	for _, snap := range snapshots {
		if snap.Timestamp.After(cutoff) {
			filtered = append(filtered, snap)
		}
	}
	filtered = append(filtered, newSnap)

	return s.saveSnapshots(filtered)
}

// GetSummary returns hourly statistics over the past N hours.
func (s *Store) GetSummary(hours int) (*HistorySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if hours <= 0 {
		hours = 24
	}

	snapshots, err := s.loadSnapshots()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	since := now.Add(-time.Duration(hours) * time.Hour)

	// Bucket by hour
	buckets := make(map[string]*HourlyReport)
	var hourKeys []string

	// Initialize all N hour slots so they appear cleanly in chronological order
	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour).Truncate(time.Hour)
		key := t.Format("2006-01-02 15:00")
		label := t.Format("15:04")
		buckets[key] = &HourlyReport{
			Hour:      t,
			HourLabel: label,
		}
		hourKeys = append(hourKeys, key)
	}

	var relevantSnapshots int
	for _, snap := range snapshots {
		if snap.Timestamp.Before(since) {
			continue
		}
		relevantSnapshots++
		hourKey := snap.Timestamp.Truncate(time.Hour).Format("2006-01-02 15:00")
		b, exists := buckets[hourKey]
		if exists {
			if snap.Connections > b.Connections {
				b.Connections = snap.Connections
			}
			b.RXBytes += snap.RXBytes
			b.TXBytes += snap.TXBytes
		}
	}

	var reports []HourlyReport
	var sumConns int
	var totalRX, totalTX uint64
	activeHours := 0

	for _, k := range hourKeys {
		r := *buckets[k]
		reports = append(reports, r)
		if r.Connections > 0 || r.RXBytes > 0 || r.TXBytes > 0 {
			activeHours++
			sumConns += r.Connections
			totalRX += r.RXBytes
			totalTX += r.TXBytes
		}
	}

	var avgConns float64
	var avgRX, avgTX uint64
	if hours > 0 {
		avgConns = float64(sumConns) / float64(hours)
		avgRX = totalRX / uint64(hours)
		avgTX = totalTX / uint64(hours)
	}

	return &HistorySummary{
		Hours:              hours,
		Reports:            reports,
		AvgConnectionsHour: avgConns,
		AvgRXHour:          avgRX,
		AvgTXHour:          avgTX,
		TotalRX:            totalRX,
		TotalTX:            totalTX,
		TotalSnapshots:     relevantSnapshots,
	}, nil
}

// Clear removes all persistent history records.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete history file %s: %w", s.filePath, err)
	}
	return nil
}

func (s *Store) loadSnapshots() ([]Snapshot, error) {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []Snapshot{}, nil
		}
		return nil, err
	}

	var snapshots []Snapshot
	if err := json.Unmarshal(data, &snapshots); err != nil {
		return []Snapshot{}, nil
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
	})

	return snapshots, nil
}

func (s *Store) saveSnapshots(snapshots []Snapshot) error {
	data, err := json.MarshalIndent(snapshots, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0644)
}
