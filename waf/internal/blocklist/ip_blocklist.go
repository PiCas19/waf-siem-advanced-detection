package blocklist

import (
	"net"
	"sync"
)

type IPBlocklist struct {
	mu    sync.RWMutex
	ips   map[string]bool
	cidrs []*net.IPNet
}

func NewIPBlocklist() *IPBlocklist {
	return &IPBlocklist{
		ips:   make(map[string]bool),
		cidrs: []*net.IPNet{},
	}
}

func (b *IPBlocklist) AddIP(ip string) {
	b.mu.Lock()
	b.ips[ip] = true
	b.mu.Unlock()
}

func (b *IPBlocklist) AddCIDR(cidr string) error {
	_, net, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.cidrs = append(b.cidrs, net)
	b.mu.Unlock()
	return nil
}

func (b *IPBlocklist) IsBlocked(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.ips[ip] {
		return true
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	for _, cidr := range b.cidrs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}