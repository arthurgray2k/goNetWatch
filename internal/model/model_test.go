package model

import (
	"net"
	"testing"
)

func TestLocalEndpoint(t *testing.T) {
	conn := &Connection{
		LocalIP:   net.ParseIP("192.168.1.50"),
		LocalPort: 54321,
	}
	if got := conn.LocalEndpoint(); got != "192.168.1.50:54321" {
		t.Errorf("expected 192.168.1.50:54321, got %s", got)
	}

	connIPv6 := &Connection{
		LocalIP:   net.ParseIP("2001:db8::1"),
		LocalPort: 443,
	}
	if got := connIPv6.LocalEndpoint(); got != "[2001:db8::1]:443" {
		t.Errorf("expected [2001:db8::1]:443, got %s", got)
	}

	connNil := &Connection{
		LocalIP:   nil,
		LocalPort: 80,
	}
	if got := connNil.LocalEndpoint(); got != "*:80" {
		t.Errorf("expected *:80, got %s", got)
	}
}

func TestRemoteEndpoint(t *testing.T) {
	conn := &Connection{
		RemoteIP:   net.ParseIP("142.250.190.46"),
		RemotePort: 443,
		RemoteHost: "google.com",
	}

	if got := conn.RemoteEndpoint(false); got != "142.250.190.46:443" {
		t.Errorf("expected 142.250.190.46:443 without resolve, got %s", got)
	}

	if got := conn.RemoteEndpoint(true); got != "google.com:443" {
		t.Errorf("expected google.com:443 with resolve, got %s", got)
	}
}
