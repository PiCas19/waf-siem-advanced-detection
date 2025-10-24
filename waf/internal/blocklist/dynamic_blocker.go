package blocklist

import (
	"sync"
	"time"
)

type DynamicBlocker struct {
	mu        sync.RWMutex
	blocked   map[string]time.Time
	duration  time.Duration
	cleanup   *time.Ticker
}

func NewDynamicBlocker(duration time.Duration) *DynamicBlocker {
	db := &DynamicBlocker{
		blocked:  make(map[string]time.Time),
		duration: duration,
		cleanup:  time.NewTicker(time.Minute),
	}
	go db.cleanupLoop()
	return db
}

func (db *DynamicBlocker) Block(ip string) {
	db.mu.Lock()
	db.blocked[ip] = time.Now().Add(db.duration)
	db.mu.Unlock()
}

func (db *DynamicBlocker) IsBlocked(ip string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if t, ok := db.blocked[ip]; ok {
		if time.Now().After(t) {
			delete(db.blocked, ip)
			return false
		}
		return true
	}
	return false
}

func (db *DynamicBlocker) cleanupLoop() {
	for range db.cleanup.C {
		db.mu.Lock()
		for ip, until := range db.blocked {
			if time.Now().After(until) {
				delete(db.blocked, ip)
			}
		}
		db.mu.Unlock()
	}
}