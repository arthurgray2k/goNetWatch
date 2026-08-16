package aggregator

import (
	"net"
	"testing"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

func TestFilterConnections(t *testing.T) {
	conns := []*model.Connection{
		{
			PID:         100,
			ProcessName: "chrome",
			RemoteIP:    net.ParseIP("142.250.190.46"),
			RemotePort:  443,
			Scope:       model.ScopeExternal,
			State:       "ESTABLISHED",
		},
		{
			PID:         200,
			ProcessName: "code",
			RemoteIP:    net.ParseIP("20.1.2.3"),
			RemoteHost:  "microsoft.com",
			RemotePort:  443,
			Scope:       model.ScopeExternal,
			State:       "ESTABLISHED",
		},
		{
			PID:         300,
			ProcessName: "cupsd",
			RemoteIP:    net.ParseIP("192.168.1.50"),
			RemotePort:  631,
			Scope:       model.ScopeLocal,
			State:       "LISTEN",
		},
	}

	// Filter by PID
	res := FilterConnections(conns, model.FilterOptions{PID: 100})
	if len(res) != 1 || res[0].ProcessName != "chrome" {
		t.Errorf("PID filter failed, got %d results", len(res))
	}

	// Filter by process name
	res = FilterConnections(conns, model.FilterOptions{ProcessName: "code"})
	if len(res) != 1 || res[0].PID != 200 {
		t.Errorf("ProcessName filter failed, got %d results", len(res))
	}

	// Filter by remote target IP or hostname
	res = FilterConnections(conns, model.FilterOptions{RemoteTarget: "192.168.1"})
	if len(res) != 1 || res[0].PID != 300 {
		t.Errorf("RemoteTarget filter failed, got %d results", len(res))
	}
	resHost := FilterConnections(conns, model.FilterOptions{RemoteTarget: "microsoft"})
	if len(resHost) != 1 || resHost[0].PID != 200 {
		t.Errorf("RemoteHost filter failed, got %d results", len(resHost))
	}

	// Filter by port
	res = FilterConnections(conns, model.FilterOptions{Port: 631})
	if len(res) != 1 || res[0].PID != 300 {
		t.Errorf("Port filter failed, got %d results", len(res))
	}

	// Filter by LocalOnly
	res = FilterConnections(conns, model.FilterOptions{LocalOnly: true})
	if len(res) != 1 || res[0].Scope != model.ScopeLocal {
		t.Errorf("LocalOnly filter failed, got %d results", len(res))
	}

	// Filter by ExternalOnly
	res = FilterConnections(conns, model.FilterOptions{ExternalOnly: true})
	if len(res) != 2 {
		t.Errorf("ExternalOnly filter failed, got %d results", len(res))
	}

	// Filter by State
	resState := FilterConnections(conns, model.FilterOptions{State: "LISTEN"})
	if len(resState) != 1 || resState[0].PID != 300 {
		t.Errorf("State filter failed, got %d results", len(resState))
	}
}

func TestAggregateByRemote(t *testing.T) {
	ip1 := net.ParseIP("142.250.190.46")
	ip2 := net.ParseIP("192.168.1.20")

	conns := []*model.Connection{
		{
			PID:         101,
			ProcessName: "chrome",
			RemoteIP:    ip1,
			RemotePort:  443,
			RXBytes:     1000,
			TXBytes:     500,
			Scope:       model.ScopeExternal,
		},
		{
			PID:         102,
			ProcessName: "chrome",
			RemoteIP:    ip1,
			RemotePort:  443,
			RemoteHost:  "google.com",
			RXBytes:     2000,
			TXBytes:     1000,
			Scope:       model.ScopeExternal,
		},
		{
			PID:         201,
			ProcessName: "smbclient",
			RemoteIP:    ip2,
			RemotePort:  445,
			RXBytes:     500,
			TXBytes:     200,
			Scope:       model.ScopeLocal,
		},
		{
			RemoteIP: nil,
		},
	}

	hosts := AggregateByRemote(conns)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 host summaries, got %d", len(hosts))
	}

	// Sorted by total traffic, host 0 should be ip1 (total 4500 vs 700)
	if hosts[0].RemoteIP.String() != ip1.String() {
		t.Errorf("expected first host to be %s, got %s", ip1, hosts[0].RemoteIP)
	}
	if hosts[0].Connections != 2 {
		t.Errorf("expected 2 connections for %s, got %d", ip1, hosts[0].Connections)
	}
	if hosts[0].RXBytes != 3000 || hosts[0].TXBytes != 1500 {
		t.Errorf("expected RX=3000, TX=1500; got RX=%d, TX=%d", hosts[0].RXBytes, hosts[0].TXBytes)
	}
	if hosts[0].RemoteHost != "google.com" {
		t.Errorf("expected RemoteHost google.com, got %s", hosts[0].RemoteHost)
	}

	localHosts, extHosts := SeparateHostsByScope(hosts)
	if len(localHosts) != 1 || len(extHosts) != 1 {
		t.Errorf("SeparateHostsByScope mismatch: local=%d, ext=%d", len(localHosts), len(extHosts))
	}
}

func TestAggregateByProcess(t *testing.T) {
	ip1 := net.ParseIP("142.250.190.46")
	ip2 := net.ParseIP("20.1.2.3")

	conns := []*model.Connection{
		{
			PID:         100,
			ProcessName: "chrome",
			User:        "mint",
			RemoteIP:    ip1,
			RXBytes:     1000,
			TXBytes:     500,
		},
		{
			PID:         100,
			ProcessName: "chrome",
			User:        "mint",
			RemoteIP:    ip2,
			RemoteHost:  "azure.com",
			RXBytes:     2000,
			TXBytes:     1000,
		},
		{
			PID:         200,
			ProcessName: "code",
			User:        "mint",
			RemoteIP:    ip2,
			RXBytes:     500,
			TXBytes:     200,
		},
	}

	procs := AggregateByProcess(conns)
	if len(procs) != 2 {
		t.Fatalf("expected 2 process summaries, got %d", len(procs))
	}

	// Chrome should be first (4500 bytes vs 700)
	if procs[0].PID != 100 || procs[0].ProcessName != "chrome" {
		t.Errorf("expected chrome (PID 100) first, got %+v", procs[0])
	}
	if procs[0].Connections != 2 {
		t.Errorf("expected 2 connections for chrome, got %d", procs[0].Connections)
	}
	if len(procs[0].RemoteHosts) != 2 {
		t.Errorf("expected 2 remote hosts for chrome, got %d", len(procs[0].RemoteHosts))
	}

	totConns, totRX, totTX := CalculateTotals(conns)
	if totConns != 3 || totRX != 3500 || totTX != 1700 {
		t.Errorf("CalculateTotals mismatch: conns=%d, rx=%d, tx=%d", totConns, totRX, totTX)
	}
}
