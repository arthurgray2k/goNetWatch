package procnet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProcNetReader_TCP(t *testing.T) {
	procNetTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 9A1DA8C0:D530 1A71528C:01BB 01 00000010:00000020 02:00000BDA 00000000  1000        0 75240 2 0000000000000000 85 4 31 10 -1
`

	entries, err := ParseProcNetReader(strings.NewReader(procNetTCP), "TCP", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].LocalIP.String() != "127.0.0.1" || entries[0].LocalPort != 80 {
		t.Errorf("entry 0: expected 127.0.0.1:80, got %s:%d", entries[0].LocalIP, entries[0].LocalPort)
	}
	if entries[0].State != "LISTEN" {
		t.Errorf("entry 0: expected LISTEN, got %s", entries[0].State)
	}
	if entries[0].Inode != 12345 {
		t.Errorf("entry 0: expected inode 12345, got %d", entries[0].Inode)
	}

	if entries[1].LocalIP.String() != "192.168.29.154" || entries[1].LocalPort != 54576 {
		t.Errorf("entry 1: expected local 192.168.29.154:54576, got %s:%d", entries[1].LocalIP, entries[1].LocalPort)
	}
	if entries[1].RemoteIP.String() != "140.82.113.26" || entries[1].RemotePort != 443 {
		t.Errorf("entry 1: expected remote 140.82.113.26:443, got %s:%d", entries[1].RemoteIP, entries[1].RemotePort)
	}
	if entries[1].State != "ESTABLISHED" {
		t.Errorf("entry 1: expected ESTABLISHED, got %s", entries[1].State)
	}
	if entries[1].TxQueue != 16 || entries[1].RxQueue != 32 {
		t.Errorf("entry 1: expected tx_queue=16, rx_queue=32, got tx=%d, rx=%d", entries[1].TxQueue, entries[1].RxQueue)
	}

	connsNotListening := entriesToConnections(entries, false)
	if len(connsNotListening) != 1 {
		t.Errorf("expected 1 active connection without listeners, got %d", len(connsNotListening))
	}

	connsAll := entriesToConnections(entries, true)
	if len(connsAll) != 2 {
		t.Errorf("expected 2 connections with all=true, got %d", len(connsAll))
	}
}

func TestParseProcNetReader_UDP(t *testing.T) {
	procNetUDP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 10101 2 0000000000000000 100 0 0 10 0
   1: 0100007F:1234 0100007F:5678 07 00000000:00000000 00:00000000 00000000  1000        0 20202 2 0000000000000000 100 0 0 10 0
   2: 00000000:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 30303 2 0000000000000000 100 0 0 10 0
`
	entries, err := ParseProcNetReader(strings.NewReader(procNetUDP), "UDP", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	conns := entriesToConnections(entries, false)
	if len(conns) != 1 {
		t.Errorf("expected 1 active connected UDP socket, got %d", len(conns))
	}
}

func TestParseIPv6AndErrors(t *testing.T) {
	// Valid IPv6 hex (32 chars)
	hexIPv6 := "00000000000000000000000001000000" // ::1 in linux format
	ip, err := parseIPHex(hexIPv6, true)
	if err != nil {
		t.Fatalf("parseIPv6Hex failed: %v", err)
	}
	if ip.String() != "::1" {
		t.Errorf("expected ::1, got %s", ip.String())
	}

	// IPv4-mapped IPv6 hex
	// ::ffff:127.0.0.1 -> 00000000 00000000 FFFF0000 0100007F
	hexMapped := "0000000000000000FFFF00000100007F"
	ipMapped, err := parseIPHex(hexMapped, true)
	if err != nil {
		t.Fatalf("parse mapped IPv6 failed: %v", err)
	}
	if ipMapped.String() != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", ipMapped.String())
	}

	// Invalid lengths
	if _, err := parseIPv4Hex("123"); err == nil {
		t.Errorf("expected error for invalid ipv4 length")
	}
	if _, err := parseIPv6Hex("123"); err == nil {
		t.Errorf("expected error for invalid ipv6 length")
	}
}

func TestMapStateAll(t *testing.T) {
	states := []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "FF"}
	for _, s := range states {
		_ = mapState(s, "TCP")
		_ = mapState(s, "UDP")
	}
}

func TestScanner_ScanConnections(t *testing.T) {
	tempDir := t.TempDir()
	netDir := filepath.Join(tempDir, "net")
	if err := os.MkdirAll(netDir, 0755); err != nil {
		t.Fatalf("failed to create net dir: %v", err)
	}

	sampleTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
`
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(sampleTCP), 0644); err != nil {
		t.Fatalf("failed to write tcp: %v", err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(sampleTCP), 0644); err != nil {
		t.Fatalf("failed to write tcp6: %v", err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "udp"), []byte(sampleTCP), 0644); err != nil {
		t.Fatalf("failed to write udp: %v", err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "udp6"), []byte(sampleTCP), 0644); err != nil {
		t.Fatalf("failed to write udp6: %v", err)
	}

	scanner := NewScanner(tempDir)
	conns, err := scanner.ScanConnections(true)
	if err != nil {
		t.Fatalf("ScanConnections failed: %v", err)
	}
	if len(conns) == 0 {
		t.Errorf("expected connections, got 0")
	}
}

func TestDevScanner_ScanDev(t *testing.T) {
	tempDir := t.TempDir()
	netDir := filepath.Join(tempDir, "net")
	if err := os.MkdirAll(netDir, 0755); err != nil {
		t.Fatalf("failed to create net dir: %v", err)
	}

	devContent := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  348563    2866    0    0    0     0          0         0   348563    2866    0    0    0     0       0          0
  eth0: 1000000    5000    1    2    0     0          0         0  2000000    6000    3    4    0     0       0          0
`
	if err := os.WriteFile(filepath.Join(netDir, "dev"), []byte(devContent), 0644); err != nil {
		t.Fatalf("failed to write dev: %v", err)
	}

	devScanner := NewDevScanner(tempDir)
	stats, err := devScanner.ScanDev()
	if err != nil {
		t.Fatalf("ScanDev failed: %v", err)
	}
	if len(stats) != 2 {
		t.Errorf("expected 2 interface stats, got %d", len(stats))
	}
}
