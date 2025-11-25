package cache

import (
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// CacheEntry contiene i dati cachati con timestamp
type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

// Cache è una cache thread-safe con TTL
type Cache struct {
	data map[string]CacheEntry
	mu   sync.RWMutex
}

// NewCache crea una nuova cache
func NewCache() *Cache {
	return &Cache{
		data: make(map[string]CacheEntry),
	}
}

// Set aggiunge/aggiorna un elemento nella cache
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}

	logger.Log.WithFields(map[string]interface{}{
		"action": "cache_set",
		"key":    key,
		"ttl_ms": ttl.Milliseconds(),
	}).Debug("Cache entry set")
}

// Get recupera un elemento dalla cache
// Ritorna il valore e un bool che indica se la chiave esiste e non è scaduta
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}

	// Controlla se è scaduto
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.Value, true
}

// Delete rimuove un elemento dalla cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
	logger.Log.WithFields(map[string]interface{}{
		"action": "cache_delete",
		"key":    key,
	}).Debug("Cache entry deleted")
}

// Clear svuota la cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]CacheEntry)
	logger.Log.WithFields(map[string]interface{}{
		"action": "cache_clear",
	}).Debug("Cache cleared")
}

// CleanupExpired rimuove gli elementi scaduti
func (c *Cache) CleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	deleted := 0

	for key, entry := range c.data {
		if now.After(entry.ExpiresAt) {
			delete(c.data, key)
			deleted++
		}
	}

	if deleted > 0 {
		logger.Log.WithFields(map[string]interface{}{
			"action":         "cache_cleanup",
			"entries_deleted": deleted,
		}).Debug("Expired cache entries cleaned up")
	}
}

// Size ritorna il numero di elementi nella cache
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.data)
}

// DefaultRulesCache è una cache globale per le regole default (non cambiano mai)
var DefaultRulesCache = NewCache()

// GeoIPCache è una cache per i risultati GeoIP lookup
var GeoIPCache = NewCache()

// InitializeCleanupWorker avvia un goroutine che pulisce la cache periodicamente
func InitializeCleanupWorker(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			DefaultRulesCache.CleanupExpired()
			GeoIPCache.CleanupExpired()
		}
	}()

	logger.Log.WithFields(map[string]interface{}{
		"action":   "cache_cleanup_worker",
		"interval": interval.Seconds(),
	}).Info("Cache cleanup worker started")
}

// CacheStats contains cache statistics
type CacheStats struct {
	DefaultRulesSize int
	GeoIPSize        int
	TotalSize        int
}

// GetStats retorna statistiche sulla cache
func GetStats() CacheStats {
	return CacheStats{
		DefaultRulesSize: DefaultRulesCache.Size(),
		GeoIPSize:        GeoIPCache.Size(),
		TotalSize:        DefaultRulesCache.Size() + GeoIPCache.Size(),
	}
}
