package dns

import (
	"net"
	"testing"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

func TestResolver_Disabled(t *testing.T) {
	r := NewResolver(false, 0)
	res := r.Resolve(net.ParseIP("8.8.8.8"))
	if res != "" {
		t.Errorf("expected empty string when disabled, got %s", res)
	}

	conns := []*model.Connection{
		{RemoteIP: net.ParseIP("8.8.8.8")},
		{RemoteIP: nil},
		{RemoteIP: net.ParseIP("127.0.0.1")},
		{RemoteIP: net.ParseIP("0.0.0.0")},
		{RemoteIP: net.ParseIP("1.1.1.1"), RemoteHost: "already.set"},
	}
	r.ResolveConnections(conns)
	if conns[0].RemoteHost != "" {
		t.Errorf("expected empty RemoteHost, got %s", conns[0].RemoteHost)
	}
}

func TestResolver_CacheAndResolve(t *testing.T) {
	r := NewResolver(true, 100*time.Millisecond)
	r.cache["1.2.3.4"] = "test.example.com"

	// Cached hit
	res := r.Resolve(net.ParseIP("1.2.3.4"))
	if res != "test.example.com" {
		t.Errorf("expected cached value test.example.com, got %s", res)
	}

	// Loopback and unspecified should return empty
	if got := r.Resolve(net.ParseIP("127.0.0.1")); got != "" {
		t.Errorf("expected empty for loopback, got %s", got)
	}
	if got := r.Resolve(nil); got != "" {
		t.Errorf("expected empty for nil IP, got %s", got)
	}

	// Non-cached with short timeout
	conns := []*model.Connection{
		{RemoteIP: net.ParseIP("1.2.3.4")},
		{RemoteIP: net.ParseIP("192.0.2.1")}, // test net IP, will likely time out or fail gracefully
	}
	r.ResolveConnections(conns)

	if conns[0].RemoteHost != "test.example.com" {
		t.Errorf("expected test.example.com, got %s", conns[0].RemoteHost)
	}
}
