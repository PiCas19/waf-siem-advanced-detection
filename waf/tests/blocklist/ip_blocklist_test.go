package blocklist

import (
	"net"
	"sync"
	"testing"
	
	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/blocklist"
)

// Copia della struttura per accedere ai campi privati
type testIPBlocklist struct {
	mu    *sync.RWMutex
	ips   map[string]bool
	cidrs []*net.IPNet
}

func TestNewIPBlocklist(t *testing.T) {
	b := blocklist.NewIPBlocklist()
	if b == nil {
		t.Fatal("NewIPBlocklist should return a non-nil pointer")
	}
}

func TestIPBlocklist_AddIP(t *testing.T) {
	b := blocklist.NewIPBlocklist()
	ip := "192.168.1.1"
	
	b.AddIP(ip)
	
	// Non possiamo accedere direttamente a b.ips perché è privato
	// Testiamo attraverso IsBlocked
	if !b.IsBlocked(ip) {
		t.Errorf("IP %s should be blocked", ip)
	}
}

func TestIPBlocklist_AddCIDR(t *testing.T) {
	b := blocklist.NewIPBlocklist()
	cidr := "192.168.1.0/24"
	
	err := b.AddCIDR(cidr)
	if err != nil {
		t.Errorf("AddCIDR should not return error for valid CIDR: %v", err)
	}
}

func TestIPBlocklist_AddCIDR_Invalid(t *testing.T) {
	b := blocklist.NewIPBlocklist()
	invalidCIDR := "not-a-cidr"
	
	err := b.AddCIDR(invalidCIDR)
	if err == nil {
		t.Error("AddCIDR should return error for invalid CIDR")
	}
}

func TestIPBlocklist_IsBlocked_IP(t *testing.T) {
	b := blocklist.NewIPBlocklist()
	ip := "10.0.0.1"
	
	b.AddIP(ip)
	
	if !b.IsBlocked(ip) {
		t.Errorf("IP %s should be blocked", ip)
	}
	
	// Test unblocked IP
	if b.IsBlocked("10.0.0.2") {
		t.Error("IP 10.0.0.2 should not be blocked")
	}
}

func TestIPBlocklist_IsBlocked_CIDR(t *testing.T) {
	b := blocklist.NewIPBlocklist()
	cidr := "172.16.0.0/16"
	
	err := b.AddCIDR(cidr)
	if err != nil {
		t.Fatalf("Failed to add CIDR: %v", err)
	}
	
	// Test IP within CIDR
	if !b.IsBlocked("172.16.1.1") {
		t.Error("IP 172.16.1.1 should be blocked (within CIDR)")
	}
	
	if !b.IsBlocked("172.16.255.254") {
		t.Error("IP 172.16.255.254 should be blocked (within CIDR)")
	}
	
	// Test IP outside CIDR
	if b.IsBlocked("172.17.0.1") {
		t.Error("IP 172.17.0.1 should not be blocked (outside CIDR)")
	}
}

func TestIPBlocklist_IsBlocked_InvalidIP(t *testing.T) {
	b := blocklist.NewIPBlocklist()
	
	// Invalid IP should return false
	if b.IsBlocked("not-an-ip") {
		t.Error("IsBlocked should return false for invalid IP")
	}
}