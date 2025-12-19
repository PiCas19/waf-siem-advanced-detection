package blocklist

import (
	"sync"
	"testing"
	"time"
	
	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/blocklist"
)

func TestNewDynamicBlocker(t *testing.T) {
	duration := 5 * time.Minute
	db := blocklist.NewDynamicBlocker(duration)
	
	if db == nil {
		t.Fatal("NewDynamicBlocker should return a non-nil pointer")
	}
	
	// Non possiamo testare i campi privati direttamente
	// Testiamo attraverso i metodi pubblici
}

func TestDynamicBlocker_Block(t *testing.T) {
	db := blocklist.NewDynamicBlocker(1 * time.Hour)
	defer func() {
		// Non possiamo accedere a db.cleanup perché è privato
		// Dovremmo aggiungere un metodo Stop() o usare defer in modo diverso
	}()
	
	ip := "192.168.1.1"
	db.Block(ip)
	
	// Testiamo attraverso IsBlocked
	if !db.IsBlocked(ip) {
		t.Error("IP should be blocked after Block()")
	}
}

func TestDynamicBlocker_IsBlocked(t *testing.T) {
	db := blocklist.NewDynamicBlocker(100 * time.Millisecond)
	
	ip := "10.0.0.1"
	
	// Initially not blocked
	if db.IsBlocked(ip) {
		t.Error("IP should not be blocked initially")
	}
	
	// Block the IP
	db.Block(ip)
	
	// Should be blocked now
	if !db.IsBlocked(ip) {
		t.Error("IP should be blocked after Block()")
	}
	
	// Wait for expiration
	time.Sleep(150 * time.Millisecond)
	
	// Should not be blocked after expiration
	if db.IsBlocked(ip) {
		t.Error("IP should not be blocked after expiration")
	}
}

func TestDynamicBlocker_ConcurrentAccess(t *testing.T) {
	db := blocklist.NewDynamicBlocker(1 * time.Minute)
	
	ips := []string{"192.168.0.1", "192.168.0.2", "192.168.0.3"}
	
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := ips[idx%len(ips)]
			
			switch idx % 3 {
			case 0:
				db.Block(ip)
			case 1:
				db.IsBlocked(ip)
			case 2:
				db.Block(ip)
				db.IsBlocked(ip)
			}
		}(i)
	}
	
	wg.Wait()
}

// TestCleanupViaIsBlocked - IsBlocked pulisce gli scaduti quando chiamato
func TestCleanupViaIsBlocked(t *testing.T) {
	db := blocklist.NewDynamicBlocker(100 * time.Millisecond)
	
	ip := "10.0.0.5"
	db.Block(ip)
	
	// Attendi che scada
	time.Sleep(150 * time.Millisecond)
	
	// IsBlocked dovrebbe rimuovere l'IP scaduto internamente
	if db.IsBlocked(ip) {
		t.Error("IsBlocked should return false and remove expired IP")
	}
	
	// Verifica che chiamate successive restituiscano false
	if db.IsBlocked(ip) {
		t.Error("Subsequent IsBlocked calls should return false")
	}
}

// TestCleanupLoop_IsBlockedTriggersCleanup - Verifica che IsBlocked pulisca
func TestCleanupLoop_IsBlockedTriggersCleanup(t *testing.T) {
	db := blocklist.NewDynamicBlocker(50 * time.Millisecond)
	
	// Blocca 3 IP
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	for _, ip := range ips {
		db.Block(ip)
	}
	
	// Attendi che scadano
	time.Sleep(100 * time.Millisecond)
	
	// Chiama IsBlocked su uno di essi - dovrebbe pulire quello specifico
	if db.IsBlocked("1.1.1.1") {
		t.Error("IsBlocked should clean expired IP 1.1.1.1")
	}
}