package classifier

import (
	"net"
	"testing"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

func TestClassifyScope(t *testing.T) {
	tests := []struct {
		ip       string
		expected model.NetworkScope
	}{
		// IPv4 Local / Private
		{"127.0.0.1", model.ScopeLocal},
		{"10.0.0.1", model.ScopeLocal},
		{"172.16.5.10", model.ScopeLocal},
		{"172.31.255.254", model.ScopeLocal},
		{"192.168.1.1", model.ScopeLocal},
		{"169.254.1.1", model.ScopeLocal},
		{"100.64.0.1", model.ScopeLocal},
		{"224.0.0.1", model.ScopeLocal},
		{"0.0.0.0", model.ScopeLocal},

		// IPv6 Local / Private
		{"::1", model.ScopeLocal},
		{"::", model.ScopeLocal},
		{"fe80::1", model.ScopeLocal},
		{"fd00::1", model.ScopeLocal},
		{"fc00::abcd", model.ScopeLocal},
		{"ff02::1", model.ScopeLocal},

		// Public / External IPv4
		{"8.8.8.8", model.ScopeExternal},
		{"1.1.1.1", model.ScopeExternal},
		{"142.250.190.46", model.ScopeExternal},
		{"140.82.113.26", model.ScopeExternal},
		{"172.32.0.1", model.ScopeExternal},

		// Public / External IPv6
		{"2001:4860:4860::8888", model.ScopeExternal},
		{"2606:4700:4700::1111", model.ScopeExternal},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %s", tt.ip)
		}
		got := ClassifyScope(ip)
		if got != tt.expected {
			t.Errorf("ClassifyScope(%s) = %v; want %v", tt.ip, got, tt.expected)
		}
	}
}
