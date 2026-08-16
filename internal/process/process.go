package process

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

// ProcessInfo contains metadata about a process owning a socket.
type ProcessInfo struct {
	PID     int
	Name    string
	User    string
	Cmdline string
}

// Mapper maps socket inodes to process information by inspecting /proc.
type Mapper struct {
	procRoot string
	mu       sync.Mutex
	uidCache map[uint32]string
}

// NewMapper creates a Mapper targeting procRoot (default "/proc").
func NewMapper(procRoot string) *Mapper {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Mapper{
		procRoot: procRoot,
		uidCache: make(map[uint32]string),
	}
}

// MapSocketsToProcesses returns a map of socket inode -> ProcessInfo.
func (m *Mapper) MapSocketsToProcesses() (map[uint64]ProcessInfo, error) {
	result := make(map[uint64]ProcessInfo)

	entries, err := os.ReadDir(m.procRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to read proc root %s: %w", m.procRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			// Not a numeric PID directory
			continue
		}

		fdDir := filepath.Join(m.procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// If permission denied or process exited, skip
			continue
		}

		// Read process name
		commPath := filepath.Join(m.procRoot, entry.Name(), "comm")
		procName := m.readProcComm(commPath)
		if procName == "" {
			procName = "unknown"
		}

		for _, fdEntry := range fds {
			linkPath := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			// Format: "socket:[<inode>]"
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inodeStr := target[8 : len(target)-1]
				inode, err := strconv.ParseUint(inodeStr, 10, 64)
				if err != nil {
					continue
				}

				if _, exists := result[inode]; !exists {
					result[inode] = ProcessInfo{
						PID:  pid,
						Name: procName,
					}
				}
			}
		}
	}

	return result, nil
}

// Correlate annotates a slice of connections with process names and PIDs.
func (m *Mapper) Correlate(conns []*model.Connection) error {
	inodeMap, err := m.MapSocketsToProcesses()
	if err != nil {
		return err
	}

	for _, c := range conns {
		if info, found := inodeMap[c.Inode]; found {
			c.PID = info.PID
			c.ProcessName = info.Name
		} else {
			if c.ProcessName == "" {
				c.ProcessName = "-"
			}
		}

		if c.User != "" {
			if uid, err := strconv.ParseUint(c.User, 10, 32); err == nil {
				c.User = m.ResolveUser(uint32(uid))
			}
		}
	}

	return nil
}

func (m *Mapper) readProcComm(commPath string) string {
	data, err := os.ReadFile(commPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ResolveUser resolves a Linux UID to a username string with caching.
func (m *Mapper) ResolveUser(uid uint32) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if name, found := m.uidCache[uid]; found {
		return name
	}

	if uid == 0 {
		m.uidCache[uid] = "root"
		return "root"
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err == nil && u.Username != "" {
		m.uidCache[uid] = u.Username
		return u.Username
	}

	uidStr := strconv.FormatUint(uint64(uid), 10)
	m.uidCache[uid] = uidStr
	return uidStr
}
