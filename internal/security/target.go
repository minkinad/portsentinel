package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Target struct {
	URL  *url.URL
	Host string
	Port int
	IP   netip.Addr
}

type Policy struct {
	AllowPrivate bool
	AllowedPorts []int
	AllowCIDRs   []netip.Prefix
	DenyCIDRs    []netip.Prefix
	Resolver     *net.Resolver
}

func (p Policy) Resolve(ctx context.Context, raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return Target{}, errors.New("target must be an HTTP(S) URL without credentials or fragment")
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Target{}, errors.New("invalid port")
		}
	}
	allowed := false
	for _, v := range p.AllowedPorts {
		if v == port {
			allowed = true
		}
	}
	if !allowed {
		return Target{}, fmt.Errorf("port %d is not allowed", port)
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		if !p.AllowPrivate {
			return Target{}, errors.New("localhost is blocked")
		}
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return Target{}, fmt.Errorf("resolve target: %w", err)
	}
	if len(ips) == 0 {
		return Target{}, errors.New("target has no IP addresses")
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !p.allowedIP(ip) {
			return Target{}, fmt.Errorf("resolved address %s is blocked", ip)
		}
	}
	return Target{URL: u, Host: host, Port: port, IP: ips[0].Unmap()}, nil
}

func (p Policy) allowedIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, cidr := range p.DenyCIDRs {
		if cidr.Contains(ip) {
			return false
		}
	}
	if len(p.AllowCIDRs) > 0 {
		found := false
		for _, cidr := range p.AllowCIDRs {
			if cidr.Contains(ip) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return p.AllowPrivate
	}
	return p.AllowPrivate || ip.IsGlobalUnicast() && !ip.IsPrivate() && !reserved(ip)
}

func reserved(ip netip.Addr) bool {
	blocks := []string{"0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001:db8::/32", "fc00::/7", "fe80::/10"}
	for _, block := range blocks {
		if netip.MustParsePrefix(block).Contains(ip) {
			return true
		}
	}
	return false
}
