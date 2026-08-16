package procnet

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InterfaceStats contains receive and transmit statistics for a network interface.
type InterfaceStats struct {
	Interface string `json:"interface"`
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDrops   uint64 `json:"rx_drops"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDrops   uint64 `json:"tx_drops"`
}

// DevScanner scans /proc/net/dev for interface stats.
type DevScanner struct {
	procRoot string
}

// NewDevScanner creates a new DevScanner.
func NewDevScanner(procRoot string) *DevScanner {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &DevScanner{procRoot: procRoot}
}

// ScanDev reads /proc/net/dev and returns statistics for all interfaces.
func (s *DevScanner) ScanDev() ([]InterfaceStats, error) {
	file, err := os.Open(filepath.Join(s.procRoot, "net", "dev"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseProcNetDev(file)
}

// ParseProcNetDev parses /proc/net/dev content from an io.Reader.
func ParseProcNetDev(r io.Reader) ([]InterfaceStats, error) {
	var stats []InterfaceStats
	scanner := bufio.NewScanner(r)

	// Skip 2 header lines
	if !scanner.Scan() || !scanner.Scan() {
		return stats, nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		iface := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 16 {
			continue
		}

		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		rxErrors, _ := strconv.ParseUint(fields[2], 10, 64)
		rxDrops, _ := strconv.ParseUint(fields[3], 10, 64)

		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)
		txErrors, _ := strconv.ParseUint(fields[10], 10, 64)
		txDrops, _ := strconv.ParseUint(fields[11], 10, 64)

		stats = append(stats, InterfaceStats{
			Interface: iface,
			RxBytes:   rxBytes,
			RxPackets: rxPackets,
			RxErrors:  rxErrors,
			RxDrops:   rxDrops,
			TxBytes:   txBytes,
			TxPackets: txPackets,
			TxErrors:  txErrors,
			TxDrops:   txDrops,
		})
	}

	return stats, scanner.Err()
}
