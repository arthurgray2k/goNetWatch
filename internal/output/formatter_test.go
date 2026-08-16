package output

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/arthurgray2k/goNetWatch/internal/history"
	"github.com/arthurgray2k/goNetWatch/internal/model"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q; want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestFormatRate(t *testing.T) {
	tests := []struct {
		bps  float64
		want string
	}{
		{500, "500 B/s"},
		{10240, "10.0 KB/s"},
		{5242880, "5.0 MB/s"},
		{2147483648, "2.0 GB/s"},
	}

	for _, tt := range tests {
		got := FormatRate(tt.bps)
		if got != tt.want {
			t.Errorf("FormatRate(%f) = %q; want %q", tt.bps, got, tt.want)
		}
	}
}

func TestPrintConnections(t *testing.T) {
	// Empty case
	bufEmpty := new(bytes.Buffer)
	PrintConnections(bufEmpty, []*model.Connection{}, false, true)
	if !strings.Contains(bufEmpty.String(), "No active network connections") {
		t.Errorf("expected no active connections message")
	}

	conns := []*model.Connection{
		{
			Protocol:    "TCP",
			LocalIP:     net.ParseIP("192.168.1.10"),
			LocalPort:   54321,
			RemoteIP:    net.ParseIP("142.250.190.46"),
			RemotePort:  443,
			RemoteHost:  "google.com",
			State:       "ESTABLISHED",
			Scope:       model.ScopeExternal,
			PID:         1234,
			ProcessName: "chrome",
			RXBytes:     1048576,
			TXBytes:     524288,
		},
		{
			Protocol:    "TCP",
			LocalIP:     net.ParseIP("192.168.1.10"),
			LocalPort:   45678,
			RemoteIP:    net.ParseIP("192.168.1.20"),
			RemotePort:  445,
			State:       "ESTABLISHED",
			Scope:       model.ScopeLocal,
			PID:         0,
			ProcessName: "-",
			RXBytes:     2048,
			TXBytes:     1024,
		},
	}

	buf := new(bytes.Buffer)
	PrintConnections(buf, conns, true, false)
	out := buf.String()

	if !strings.Contains(out, "EXTERNAL / INTERNET") {
		t.Errorf("expected EXTERNAL section in output: %s", out)
	}
	if !strings.Contains(out, "LOCAL NETWORK") {
		t.Errorf("expected LOCAL NETWORK section in output: %s", out)
	}
	if !strings.Contains(out, "google.com:443") {
		t.Errorf("expected google.com:443 in output: %s", out)
	}
	if !strings.Contains(out, "chrome") {
		t.Errorf("expected chrome in output: %s", out)
	}
}

func TestPrintRemoteAggregation(t *testing.T) {
	// Empty case
	bufEmpty := new(bytes.Buffer)
	PrintRemoteAggregation(bufEmpty, []*model.HostSummary{}, false, true)
	if !strings.Contains(bufEmpty.String(), "No matching remote hosts") {
		t.Errorf("expected no matching hosts message")
	}

	hosts := []*model.HostSummary{
		{
			RemoteIP:    net.ParseIP("142.250.190.46"),
			RemoteHost:  "google.com",
			Scope:       model.ScopeExternal,
			Connections: 5,
			Processes:   []string{"chrome"},
			RXBytes:     50000,
			TXBytes:     25000,
		},
		{
			RemoteIP:    net.ParseIP("192.168.1.50"),
			Scope:       model.ScopeLocal,
			Connections: 2,
			Processes:   []string{},
			RXBytes:     1000,
			TXBytes:     500,
		},
	}

	buf := new(bytes.Buffer)
	PrintRemoteAggregation(buf, hosts, true, false)
	out := buf.String()

	if !strings.Contains(out, "google.com") {
		t.Errorf("expected google.com in output: %s", out)
	}
	if !strings.Contains(out, "192.168.1.50") {
		t.Errorf("expected 192.168.1.50 in output: %s", out)
	}
}

func TestPrintProcessAggregation(t *testing.T) {
	// Empty case
	bufEmpty := new(bytes.Buffer)
	PrintProcessAggregation(bufEmpty, []*model.ProcessSummary{}, true)
	if !strings.Contains(bufEmpty.String(), "No matching processes") {
		t.Errorf("expected no matching processes message")
	}

	procs := []*model.ProcessSummary{
		{
			PID:         1234,
			ProcessName: "chrome",
			User:        "mint",
			Connections: 8,
			RemoteHosts: []string{"google.com", "1.1.1.1"},
			RXBytes:     100000,
			TXBytes:     50000,
		},
		{
			PID:         0,
			ProcessName: "-",
			User:        "",
			Connections: 1,
			RemoteHosts: []string{},
			RXBytes:     100,
			TXBytes:     50,
		},
	}

	buf := new(bytes.Buffer)
	PrintProcessAggregation(buf, procs, false)
	out := buf.String()

	if !strings.Contains(out, "chrome") {
		t.Errorf("expected chrome in output: %s", out)
	}
	if !strings.Contains(out, "1234") {
		t.Errorf("expected PID 1234 in output: %s", out)
	}
}

func TestPrintHistory(t *testing.T) {
	summary := &history.HistorySummary{
		Hours: 24,
		Reports: []history.HourlyReport{
			{
				HourLabel:   "12:00",
				Connections: 10,
				RXBytes:     1024000,
				TXBytes:     512000,
			},
		},
		AvgConnectionsHour: 10.0,
		AvgRXHour:          1024000,
		AvgTXHour:          512000,
		TotalRX:            1024000,
		TotalTX:            512000,
		TotalSnapshots:     0,
	}

	buf := new(bytes.Buffer)
	PrintHistory(buf, summary, false)
	out := buf.String()

	if !strings.Contains(out, "NETWORK ACTIVITY — LAST 24 HOURS") {
		t.Errorf("expected header in output: %s", out)
	}
	if !strings.Contains(out, "12:00") {
		t.Errorf("expected 12:00 in output: %s", out)
	}
	if !strings.Contains(out, "No historical snapshots recorded yet") {
		t.Errorf("expected snapshot notice in output: %s", out)
	}
}

func TestPrintJSON(t *testing.T) {
	data := map[string]string{"status": "ok"}
	buf := new(bytes.Buffer)
	if err := PrintJSON(buf, data); err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}
	if !strings.Contains(buf.String(), `"status": "ok"`) {
		t.Errorf("unexpected JSON output: %s", buf.String())
	}
}
