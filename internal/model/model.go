package model

import (
	"fmt"
	"net"
	"time"
)

// NetworkScope defines whether an endpoint belongs to the local network or internet/external.
type NetworkScope string

const (
	ScopeLocal    NetworkScope = "LOCAL NETWORK"
	ScopeExternal NetworkScope = "EXTERNAL"
)

// Connection represents an active or observed network connection/socket.
type Connection struct {
	Protocol    string        `json:"protocol"`              // "TCP" or "UDP"
	LocalIP     net.IP        `json:"local_ip"`              // Local IP address
	LocalPort   int           `json:"local_port"`            // Local port
	RemoteIP    net.IP        `json:"remote_ip"`             // Remote IP address
	RemotePort  int           `json:"remote_port"`           // Remote port
	RemoteHost  string        `json:"remote_host,omitempty"` // Resolved DNS host name (if --resolve is enabled)
	State       string        `json:"state"`                 // e.g. "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"
	Scope       NetworkScope  `json:"scope"`                 // "LOCAL NETWORK" or "EXTERNAL"
	PID         int           `json:"pid"`                   // Process ID (0 if unavailable / permission denied)
	ProcessName string        `json:"process"`               // e.g. "chrome", "code", "sshd", or "-"
	User        string        `json:"user,omitempty"`        // Username or UID string
	Inode       uint64        `json:"inode"`                 // Socket inode
	RXBytes     uint64        `json:"rx_bytes"`              // Bytes received (cumulative on socket)
	TXBytes     uint64        `json:"tx_bytes"`              // Bytes transmitted / acked (cumulative on socket)
	RXRate      float64       `json:"rx_rate_bps,omitempty"` // RX rate in bytes/sec
	TXRate      float64       `json:"tx_rate_bps,omitempty"` // TX rate in bytes/sec
	RTT         time.Duration `json:"rtt,omitempty"`         // Round-trip time if available
}

// LocalEndpoint returns formatted local address "IP:port" (or "[IPv6]:port").
func (c *Connection) LocalEndpoint() string {
	return formatEndpoint(c.LocalIP, c.LocalPort)
}

// RemoteEndpoint returns formatted remote address "IP:port" (or "[IPv6]:port" or "host:port").
func (c *Connection) RemoteEndpoint(preferHost bool) string {
	if preferHost && c.RemoteHost != "" {
		return fmt.Sprintf("%s:%d", c.RemoteHost, c.RemotePort)
	}
	return formatEndpoint(c.RemoteIP, c.RemotePort)
}

func formatEndpoint(ip net.IP, port int) string {
	if ip == nil {
		return fmt.Sprintf("*:%d", port)
	}
	if ip.To4() == nil && len(ip) == 16 {
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// HostSummary aggregates connection and traffic statistics by remote endpoint/host.
type HostSummary struct {
	RemoteIP    net.IP       `json:"remote_ip"`
	RemoteHost  string       `json:"remote_host,omitempty"`
	Scope       NetworkScope `json:"scope"`
	Connections int          `json:"connections"`
	RXBytes     uint64       `json:"rx_bytes"`
	TXBytes     uint64       `json:"tx_bytes"`
	Processes   []string     `json:"processes"`
	PIDs        []int        `json:"pids"`
}

// ProcessSummary aggregates connection and traffic statistics by process/PID.
type ProcessSummary struct {
	PID         int      `json:"pid"`
	ProcessName string   `json:"process"`
	User        string   `json:"user,omitempty"`
	Connections int      `json:"connections"`
	RXBytes     uint64   `json:"rx_bytes"`
	TXBytes     uint64   `json:"tx_bytes"`
	RemoteHosts []string `json:"remote_hosts"`
}

// FilterOptions holds parameters for filtering network connections.
type FilterOptions struct {
	PID          int
	ProcessName  string
	RemoteTarget string
	Port         int
	LocalOnly    bool
	ExternalOnly bool
	State        string
}
