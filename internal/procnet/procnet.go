package procnet

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/arthurgray2k/goNetWatch/internal/classifier"
	"github.com/arthurgray2k/goNetWatch/internal/model"
)

// SocketEntry holds raw parsed socket information from /proc/net/*.
type SocketEntry struct {
	Protocol    string
	LocalIP     net.IP
	LocalPort   int
	RemoteIP    net.IP
	RemotePort  int
	State       string
	UID         uint32
	Inode       uint64
	TxQueue     uint64
	RxQueue     uint64
	RawLocalStr string
}

// Scanner scans /proc/net files for sockets.
type Scanner struct {
	procRoot string
}

// NewScanner creates a new Scanner targeting procRoot (default "/proc").
func NewScanner(procRoot string) *Scanner {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Scanner{procRoot: procRoot}
}

// ScanConnections scans TCP and UDP connections from /proc/net.
func (s *Scanner) ScanConnections(includeListening bool) ([]*model.Connection, error) {
	var conns []*model.Connection

	tcpEntries, err := s.scanFile(filepath.Join(s.procRoot, "net", "tcp"), "TCP", false)
	if err == nil {
		conns = append(conns, entriesToConnections(tcpEntries, includeListening)...)
	}

	tcp6Entries, err := s.scanFile(filepath.Join(s.procRoot, "net", "tcp6"), "TCP", true)
	if err == nil {
		conns = append(conns, entriesToConnections(tcp6Entries, includeListening)...)
	}

	udpEntries, err := s.scanFile(filepath.Join(s.procRoot, "net", "udp"), "UDP", false)
	if err == nil {
		conns = append(conns, entriesToConnections(udpEntries, includeListening)...)
	}

	udp6Entries, err := s.scanFile(filepath.Join(s.procRoot, "net", "udp6"), "UDP", true)
	if err == nil {
		conns = append(conns, entriesToConnections(udp6Entries, includeListening)...)
	}

	return conns, nil
}

func (s *Scanner) scanFile(path string, proto string, isIPv6 bool) ([]SocketEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParseProcNetReader(file, proto, isIPv6)
}

// ParseProcNetReader parses /proc/net format from an io.Reader.
func ParseProcNetReader(r io.Reader, proto string, isIPv6 bool) ([]SocketEntry, error) {
	scanner := bufio.NewScanner(r)
	var entries []SocketEntry

	// Skip header line
	if !scanner.Scan() {
		return entries, nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// fields[1]: local_address
		// fields[2]: rem_address
		// fields[3]: st
		// fields[4]: tx_queue:rx_queue
		// fields[7]: uid
		// fields[9]: inode

		stateHex := fields[3]
		stateStr := mapState(stateHex, proto)

		localParts := strings.Split(fields[1], ":")
		if len(localParts) != 2 {
			continue
		}

		localIP, err := parseIPHex(localParts[0], isIPv6)
		if err != nil {
			continue
		}

		localPort, err := strconv.ParseUint(localParts[1], 16, 16)
		if err != nil {
			continue
		}

		remParts := strings.Split(fields[2], ":")
		if len(remParts) != 2 {
			continue
		}

		remoteIP, err := parseIPHex(remParts[0], isIPv6)
		if err != nil {
			continue
		}

		remotePort, err := strconv.ParseUint(remParts[1], 16, 16)
		if err != nil {
			continue
		}

		// Queue buffers tx_queue:rx_queue
		var txQueue, rxQueue uint64
		queueParts := strings.Split(fields[4], ":")
		if len(queueParts) == 2 {
			txQueue, _ = strconv.ParseUint(queueParts[0], 16, 64)
			rxQueue, _ = strconv.ParseUint(queueParts[1], 16, 64)
		}

		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		entries = append(entries, SocketEntry{
			Protocol:    proto,
			LocalIP:     localIP,
			LocalPort:   int(localPort),
			RemoteIP:    remoteIP,
			RemotePort:  int(remotePort),
			State:       stateStr,
			UID:         uint32(uid),
			Inode:       inode,
			TxQueue:     txQueue,
			RxQueue:     rxQueue,
			RawLocalStr: fields[1],
		})
	}

	return entries, scanner.Err()
}

func mapState(stateHex string, proto string) string {
	if proto == "TCP" {
		switch strings.ToUpper(stateHex) {
		case "01":
			return "ESTABLISHED"
		case "02":
			return "SYN_SENT"
		case "03":
			return "SYN_RECV"
		case "04":
			return "FIN_WAIT1"
		case "05":
			return "FIN_WAIT2"
		case "06":
			return "TIME_WAIT"
		case "07":
			return "CLOSE"
		case "08":
			return "CLOSE_WAIT"
		case "09":
			return "LAST_ACK"
		case "0A":
			return "LISTEN"
		case "0B":
			return "CLOSING"
		default:
			return "UNKNOWN"
		}
	}

	// UDP
	switch strings.ToUpper(stateHex) {
	case "07":
		return "ESTABLISHED"
	case "0A":
		return "LISTEN"
	default:
		return "UNCONN"
	}
}

func entriesToConnections(entries []SocketEntry, includeListening bool) []*model.Connection {
	var conns []*model.Connection
	for _, e := range entries {
		if !includeListening {
			if e.State == "LISTEN" || e.State == "UNCONN" {
				continue
			}
			if e.Protocol == "UDP" && (e.RemotePort == 0 || e.RemoteIP.IsUnspecified()) {
				continue
			}
		}

		scope := classifier.ClassifyScope(e.RemoteIP)
		conns = append(conns, &model.Connection{
			Protocol:   e.Protocol,
			LocalIP:    e.LocalIP,
			LocalPort:  e.LocalPort,
			RemoteIP:   e.RemoteIP,
			RemotePort: e.RemotePort,
			State:      e.State,
			Scope:      scope,
			Inode:      e.Inode,
			User:       fmt.Sprintf("%d", e.UID),
			RXBytes:    e.RxQueue,
			TXBytes:    e.TxQueue,
		})
	}
	return conns
}

func parseIPHex(hexIP string, isIPv6 bool) (net.IP, error) {
	if isIPv6 {
		return parseIPv6Hex(hexIP)
	}
	return parseIPv4Hex(hexIP)
}

func parseIPv4Hex(hexIP string) (net.IP, error) {
	if len(hexIP) != 8 {
		return nil, fmt.Errorf("invalid IPv4 hex length: %d", len(hexIP))
	}
	val, err := strconv.ParseUint(hexIP, 16, 32)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, uint32(val))
	return ip, nil
}

func parseIPv6Hex(hexIP string) (net.IP, error) {
	if len(hexIP) != 32 {
		return nil, fmt.Errorf("invalid IPv6 hex length: %d", len(hexIP))
	}

	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		wordHex := hexIP[i*8 : (i+1)*8]
		val, err := strconv.ParseUint(wordHex, 16, 32)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(ip[i*4:(i+1)*4], uint32(val))
	}

	if ip4 := ip.To4(); ip4 != nil && isIPv4Mapped(ip) {
		return ip4, nil
	}

	return ip, nil
}

func isIPv4Mapped(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[10] == 0xff && ip[11] == 0xff
}
