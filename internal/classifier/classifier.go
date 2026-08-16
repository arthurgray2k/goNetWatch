package classifier

import (
	"net"

	"github.com/arthurgray2k/goNetWatch/internal/model"
)

var privateCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		// IPv4 Loopback & Unspecified
		"127.0.0.0/8",
		"0.0.0.0/8",
		// IPv4 Private (RFC 1918)
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// IPv4 Link-Local (RFC 3927)
		"169.254.0.0/16",
		// IPv4 CGNAT (RFC 6598)
		"100.64.0.0/10",
		// IPv4 Multicast & Broadcast
		"224.0.0.0/4",
		"255.255.255.255/32",
		// IPv6 Loopback & Unspecified
		"::1/128",
		"::/128",
		// IPv6 Unique Local Address (RFC 4193)
		"fc00::/7",
		// IPv6 Link-Local
		"fe80::/10",
		// IPv6 Multicast
		"ff00::/8",
	}

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, ipnet)
		}
	}
}

// IsLocalIP returns true if the IP is private, loopback, link-local, or local subnet.
func IsLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Normalize IPv4-mapped IPv6 (::ffff:192.168.1.1)
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	for _, block := range privateCIDRs {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

// ClassifyScope returns ScopeLocal for private/local IPs and ScopeExternal for internet IPs.
func ClassifyScope(ip net.IP) model.NetworkScope {
	if IsLocalIP(ip) {
		return model.ScopeLocal
	}
	return model.ScopeExternal
}
