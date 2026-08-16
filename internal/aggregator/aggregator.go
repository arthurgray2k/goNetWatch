package aggregator

import (
	"sort"
	"strings"

	"github.com/arthurgray2k/goNetWatch/internal/classifier"
	"github.com/arthurgray2k/goNetWatch/internal/model"
)

// FilterConnections filters a list of connections according to the provided options.
func FilterConnections(conns []*model.Connection, opts model.FilterOptions) []*model.Connection {
	var filtered []*model.Connection

	procFilter := strings.ToLower(strings.TrimSpace(opts.ProcessName))
	remoteFilter := strings.ToLower(strings.TrimSpace(opts.RemoteTarget))
	stateFilter := strings.ToUpper(strings.TrimSpace(opts.State))

	for _, c := range conns {
		// Filter by PID
		if opts.PID > 0 && c.PID != opts.PID {
			continue
		}

		// Filter by Process Name
		if procFilter != "" {
			if !strings.Contains(strings.ToLower(c.ProcessName), procFilter) {
				continue
			}
		}

		// Filter by Remote IP or Host
		if remoteFilter != "" {
			matched := false
			if c.RemoteIP != nil && strings.Contains(strings.ToLower(c.RemoteIP.String()), remoteFilter) {
				matched = true
			}
			if c.RemoteHost != "" && strings.Contains(strings.ToLower(c.RemoteHost), remoteFilter) {
				matched = true
			}
			if !matched {
				continue
			}
		}

		// Filter by Port
		if opts.Port > 0 {
			if c.LocalPort != opts.Port && c.RemotePort != opts.Port {
				continue
			}
		}

		// Filter by Scope
		if opts.LocalOnly && c.Scope != model.ScopeLocal {
			continue
		}
		if opts.ExternalOnly && c.Scope != model.ScopeExternal {
			continue
		}

		// Filter by State
		if stateFilter != "" && strings.ToUpper(c.State) != stateFilter {
			continue
		}

		filtered = append(filtered, c)
	}

	return filtered
}

// AggregateByRemote groups connections by remote IP address.
func AggregateByRemote(conns []*model.Connection) []*model.HostSummary {
	groups := make(map[string]*model.HostSummary)
	procSeen := make(map[string]map[string]bool)
	pidSeen := make(map[string]map[int]bool)

	for _, c := range conns {
		if c.RemoteIP == nil {
			continue
		}
		key := c.RemoteIP.String()

		summary, exists := groups[key]
		if !exists {
			summary = &model.HostSummary{
				RemoteIP:    c.RemoteIP,
				RemoteHost:  c.RemoteHost,
				Scope:       c.Scope,
				Connections: 0,
				RXBytes:     0,
				TXBytes:     0,
				Processes:   []string{},
				PIDs:        []int{},
			}
			if summary.Scope == "" {
				summary.Scope = classifier.ClassifyScope(c.RemoteIP)
			}
			groups[key] = summary
			procSeen[key] = make(map[string]bool)
			pidSeen[key] = make(map[int]bool)
		}

		summary.Connections++
		summary.RXBytes += c.RXBytes
		summary.TXBytes += c.TXBytes

		if summary.RemoteHost == "" && c.RemoteHost != "" {
			summary.RemoteHost = c.RemoteHost
		}

		if c.ProcessName != "" && c.ProcessName != "-" && !procSeen[key][c.ProcessName] {
			procSeen[key][c.ProcessName] = true
			summary.Processes = append(summary.Processes, c.ProcessName)
		}

		if c.PID > 0 && !pidSeen[key][c.PID] {
			pidSeen[key][c.PID] = true
			summary.PIDs = append(summary.PIDs, c.PID)
		}
	}

	var results []*model.HostSummary
	for _, s := range groups {
		results = append(results, s)
	}

	// Sort by total traffic descending, then connection count descending
	sort.Slice(results, func(i, j int) bool {
		totalI := results[i].RXBytes + results[i].TXBytes
		totalJ := results[j].RXBytes + results[j].TXBytes
		if totalI != totalJ {
			return totalI > totalJ
		}
		return results[i].Connections > results[j].Connections
	})

	return results
}

// AggregateByProcess groups connections by process / PID.
func AggregateByProcess(conns []*model.Connection) []*model.ProcessSummary {
	type procKey struct {
		pid  int
		name string
	}

	groups := make(map[procKey]*model.ProcessSummary)
	hostSeen := make(map[procKey]map[string]bool)

	for _, c := range conns {
		pName := c.ProcessName
		if pName == "" {
			pName = "-"
		}
		key := procKey{pid: c.PID, name: pName}

		summary, exists := groups[key]
		if !exists {
			summary = &model.ProcessSummary{
				PID:         c.PID,
				ProcessName: pName,
				User:        c.User,
				Connections: 0,
				RXBytes:     0,
				TXBytes:     0,
				RemoteHosts: []string{},
			}
			groups[key] = summary
			hostSeen[key] = make(map[string]bool)
		}

		summary.Connections++
		summary.RXBytes += c.RXBytes
		summary.TXBytes += c.TXBytes

		if summary.User == "" && c.User != "" {
			summary.User = c.User
		}

		remoteStr := ""
		if c.RemoteHost != "" {
			remoteStr = c.RemoteHost
		} else if c.RemoteIP != nil {
			remoteStr = c.RemoteIP.String()
		}

		if remoteStr != "" && !hostSeen[key][remoteStr] {
			hostSeen[key][remoteStr] = true
			summary.RemoteHosts = append(summary.RemoteHosts, remoteStr)
		}
	}

	var results []*model.ProcessSummary
	for _, s := range groups {
		results = append(results, s)
	}

	// Sort by total traffic descending, then connection count descending
	sort.Slice(results, func(i, j int) bool {
		totalI := results[i].RXBytes + results[i].TXBytes
		totalJ := results[j].RXBytes + results[j].TXBytes
		if totalI != totalJ {
			return totalI > totalJ
		}
		return results[i].Connections > results[j].Connections
	})

	return results
}

// SeparateByScope partitions connections into Local Network and External.
func SeparateByScope(conns []*model.Connection) (local []*model.Connection, external []*model.Connection) {
	for _, c := range conns {
		if c.Scope == model.ScopeLocal {
			local = append(local, c)
		} else {
			external = append(external, c)
		}
	}
	return local, external
}

// SeparateHostsByScope partitions host summaries into Local and External.
func SeparateHostsByScope(hosts []*model.HostSummary) (local []*model.HostSummary, external []*model.HostSummary) {
	for _, h := range hosts {
		if h.Scope == model.ScopeLocal {
			local = append(local, h)
		} else {
			external = append(external, h)
		}
	}
	return local, external
}

// CalculateTotals sums total connections, RX bytes, and TX bytes.
func CalculateTotals(conns []*model.Connection) (totalConns int, totalRX uint64, totalTX uint64) {
	for _, c := range conns {
		totalConns++
		totalRX += c.RXBytes
		totalTX += c.TXBytes
	}
	return totalConns, totalRX, totalTX
}
