package process

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

func TestMapper(t *testing.T) {
	tempDir := t.TempDir()

	// Create fake /proc/1234/fd/3 -> socket:[9999]
	pid1234 := filepath.Join(tempDir, "1234")
	if err := os.MkdirAll(filepath.Join(pid1234, "fd"), 0755); err != nil {
		t.Fatalf("failed to create fake pid dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(pid1234, "comm"), []byte("mydaemon\n"), 0644); err != nil {
		t.Fatalf("failed to write comm: %v", err)
	}

	// Symlink socket:[9999]
	fd3 := filepath.Join(pid1234, "fd", "3")
	if err := os.Symlink("socket:[9999]", fd3); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Also create non-socket link and non-directory files to test robustness
	if err := os.Symlink("/dev/null", filepath.Join(pid1234, "fd", "0")); err != nil {
		t.Fatalf("failed to create null symlink: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "stat"), []byte("cpu"), 0644); err != nil {
		t.Fatalf("failed to write stat: %v", err)
	}

	mapper := NewMapper(tempDir)
	inodeMap, err := mapper.MapSocketsToProcesses()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, exists := inodeMap[9999]
	if !exists {
		t.Fatalf("expected inode 9999 to be mapped")
	}
	if info.PID != 1234 || info.Name != "mydaemon" {
		t.Errorf("expected PID 1234 and Name mydaemon, got %+v", info)
	}

	conns := []*model.Connection{
		{
			Inode: 9999,
			User:  "0",
		},
		{
			Inode: 8888,
			User:  "99999",
		},
	}

	if err := mapper.Correlate(conns); err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if conns[0].PID != 1234 || conns[0].ProcessName != "mydaemon" || conns[0].User != "root" {
		t.Errorf("conn 0 correlation mismatch: %+v", conns[0])
	}
	if conns[1].PID != 0 || conns[1].ProcessName != "-" {
		t.Errorf("conn 1 expected empty correlation, got %+v", conns[1])
	}

	// Test ResolveUser cache and non-zero UID lookup
	u1 := mapper.ResolveUser(0)
	if u1 != "root" {
		t.Errorf("expected root for uid 0, got %s", u1)
	}
	uCached := mapper.ResolveUser(0)
	if uCached != "root" {
		t.Errorf("expected cached root, got %s", uCached)
	}
	uOther := mapper.ResolveUser(99999)
	if uOther == "" {
		t.Errorf("expected non-empty string for uid 99999")
	}
}
