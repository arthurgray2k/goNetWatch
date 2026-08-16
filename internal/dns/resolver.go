package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

// Resolver handles safe reverse DNS lookups with timeout and caching.
type Resolver struct {
	mu      sync.RWMutex
	cache   map[string]string
	timeout time.Duration
	enabled bool
}

// NewResolver creates a new Resolver.
func NewResolver(enabled bool, timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	return &Resolver{
		cache:   make(map[string]string),
		timeout: timeout,
		enabled: enabled,
	}
}

// Resolve returns the reverse DNS name for an IP, or empty string if disabled/failed.
func (r *Resolver) Resolve(ip net.IP) string {
	if !r.enabled || ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}

	ipStr := ip.String()

	r.mu.RLock()
	name, found := r.cache[ipStr]
	r.mu.RUnlock()
	if found {
		return name
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	var netResolver net.Resolver
	names, err := netResolver.LookupAddr(ctx, ipStr)

	r.mu.Lock()
	defer r.mu.Unlock()

	if err == nil && len(names) > 0 {
		// Strip trailing dot
		host := strings.TrimSuffix(names[0], ".")
		r.cache[ipStr] = host
		return host
	}

	r.cache[ipStr] = ""
	return ""
}

// ResolveConnections resolves remote hosts for a list of connections.
func (r *Resolver) ResolveConnections(conns []*model.Connection) {
	if !r.enabled {
		return
	}

	var wg sync.WaitGroup
	// Limit concurrency for lookups
	sem := make(chan struct{}, 16)

	for _, c := range conns {
		if c.RemoteIP == nil || c.RemoteHost != "" {
			continue
		}

		wg.Add(1)
		go func(conn *model.Connection) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn.RemoteHost = r.Resolve(conn.RemoteIP)
		}(c)
	}

	wg.Wait()
}
