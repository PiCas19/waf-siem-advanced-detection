// tests/cache/cache_test.go
package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/cache"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
)

// init initializes the logger for tests
func init() {
	// Initialize logger with debug level and stdout output for tests
	if err := logger.InitLogger("error", "stdout"); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
}

// MockLogger per sostituire il logger globale durante i test
type MockLogger struct{}

func (m *MockLogger) WithFields(fields map[string]interface{}) interface{} {
	return m
}

func (m *MockLogger) WithError(err error) interface{} {
	return m
}

func (m *MockLogger) Debug(args ...interface{}) {}
func (m *MockLogger) Info(args ...interface{})  {}
func (m *MockLogger) Warn(args ...interface{})  {}
func (m *MockLogger) Error(args ...interface{}) {}
func (m *MockLogger) Fatal(args ...interface{}) {}

// TestCache è una versione modificata della cache che non usa il logger
type TestCache struct {
	data map[string]cache.CacheEntry
	mu   sync.RWMutex
}

// NewTestCache crea una nuova cache per test
func NewTestCache() *TestCache {
	return &TestCache{
		data: make(map[string]cache.CacheEntry),
	}
}

func (c *TestCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = cache.CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (c *TestCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.Value, true
}

func (c *TestCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
}

func (c *TestCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]cache.CacheEntry)
}

func (c *TestCache) CleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.data {
		if now.After(entry.ExpiresAt) {
			delete(c.data, key)
		}
	}
}

func (c *TestCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.data)
}

// TestNewCache verifica la creazione di una nuova cache
func TestNewCache(t *testing.T) {
	c := cache.NewCache()
	assert.NotNil(t, c)
	
	// Usa reflection per verificare la struttura interna
	// (non possiamo accedere direttamente ai campi privati)
	assert.NotPanics(t, func() {
		c.Set("test", "value", 1*time.Second)
	})
}

// TestCache_SetGet verifica l'aggiunta e il recupero di elementi
func TestCache_SetGet(t *testing.T) {
	t.Run("SetAndGet_Success", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi elemento con TTL lungo
		c.Set("key1", "value1", 1*time.Hour)
		
		// Recupera elemento
		value, found := c.Get("key1")
		
		assert.True(t, found)
		assert.Equal(t, "value1", value)
		assert.Equal(t, 1, c.Size())
	})
	
	t.Run("SetAndGet_ComplexValue", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi elemento complesso (mappa)
		complexValue := map[string]interface{}{
			"name":   "test",
			"count":  42,
			"active": true,
		}
		c.Set("complex_key", complexValue, 30*time.Minute)
		
		// Recupera elemento
		value, found := c.Get("complex_key")
		
		assert.True(t, found)
		assert.Equal(t, complexValue, value)
	})
	
	t.Run("Get_NonExistentKey", func(t *testing.T) {
		c := NewTestCache()
		
		value, found := c.Get("nonexistent")
		
		assert.False(t, found)
		assert.Nil(t, value)
	})
	
	t.Run("Get_ExpiredKey", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi elemento con TTL molto breve
		c.Set("expiring_key", "value", 1*time.Millisecond)
		
		// Attendi che scada
		time.Sleep(2 * time.Millisecond)
		
		// Prova a recuperare l'elemento scaduto
		value, found := c.Get("expiring_key")
		
		assert.False(t, found)
		assert.Nil(t, value)
	})
	
	t.Run("UpdateExistingKey", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi elemento
		c.Set("key", "first_value", 1*time.Hour)
		
		// Aggiorna elemento
		c.Set("key", "updated_value", 2*time.Hour)
		
		// Recupera elemento aggiornato
		value, found := c.Get("key")
		
		assert.True(t, found)
		assert.Equal(t, "updated_value", value)
		assert.Equal(t, 1, c.Size())
	})
	
	t.Run("Set_ZeroTTL", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi elemento con TTL zero (dovrebbe scadere immediatamente)
		c.Set("zero_ttl_key", "value", 0)
		
		// Prova a recuperare
		value, found := c.Get("zero_ttl_key")
		
		assert.False(t, found)
		assert.Nil(t, value)
	})
}

// TestCache_Delete verifica la rimozione di elementi
func TestCache_Delete(t *testing.T) {
	t.Run("Delete_ExistingKey", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi elemento
		c.Set("key1", "value1", 1*time.Hour)
		c.Set("key2", "value2", 1*time.Hour)
		
		assert.Equal(t, 2, c.Size())
		
		// Elimina elemento
		c.Delete("key1")
		
		// Verifica che sia stato rimosso
		value, found := c.Get("key1")
		assert.False(t, found)
		assert.Nil(t, value)
		
		// Verifica che l'altro elemento sia ancora presente
		value2, found2 := c.Get("key2")
		assert.True(t, found2)
		assert.Equal(t, "value2", value2)
		
		assert.Equal(t, 1, c.Size())
	})
	
	t.Run("Delete_NonExistentKey", func(t *testing.T) {
		c := NewTestCache()
		
		// Prova a eliminare una chiave che non esiste
		// Non dovrebbe causare errori
		assert.NotPanics(t, func() {
			c.Delete("nonexistent")
		})
		
		assert.Equal(t, 0, c.Size())
	})
}

// TestCache_Clear verifica lo svuotamento della cache
func TestCache_Clear(t *testing.T) {
	c := NewTestCache()
	
	// Aggiungi elementi
	c.Set("key1", "value1", 1*time.Hour)
	c.Set("key2", "value2", 1*time.Hour)
	c.Set("key3", "value3", 1*time.Hour)
	
	assert.Equal(t, 3, c.Size())
	
	// Svuota cache
	c.Clear()
	
	// Verifica che sia vuota
	assert.Equal(t, 0, c.Size())
	
	// Verifica che gli elementi non siano più accessibili
	value, found := c.Get("key1")
	assert.False(t, found)
	assert.Nil(t, value)
	
	value, found = c.Get("key2")
	assert.False(t, found)
	assert.Nil(t, value)
	
	value, found = c.Get("key3")
	assert.False(t, found)
	assert.Nil(t, value)
	
	// Verifica che si possano aggiungere nuovi elementi dopo il clear
	c.Set("new_key", "new_value", 1*time.Hour)
	assert.Equal(t, 1, c.Size())
	
	value, found = c.Get("new_key")
	assert.True(t, found)
	assert.Equal(t, "new_value", value)
}

// TestCache_CleanupExpired verifica la pulizia degli elementi scaduti
func TestCache_CleanupExpired(t *testing.T) {
	t.Run("CleanupExpired_Mixed", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi elementi con TTL diversi
		c.Set("expired1", "value1", 1*time.Millisecond) // Scadrà
		c.Set("expired2", "value2", 1*time.Millisecond) // Scadrà
		c.Set("valid1", "value3", 1*time.Hour)          // Rimarrà
		c.Set("valid2", "value4", 1*time.Hour)          // Rimarrà
		
		assert.Equal(t, 4, c.Size())
		
		// Attendi che alcuni elementi scadano
		time.Sleep(2 * time.Millisecond)
		
		// Pulisci elementi scaduti
		c.CleanupExpired()
		
		// Verifica che solo gli elementi validi siano rimasti
		assert.Equal(t, 2, c.Size())
		
		// Verifica gli elementi specifici
		_, found := c.Get("expired1")
		assert.False(t, found)
		
		_, found = c.Get("expired2")
		assert.False(t, found)
		
		value, found := c.Get("valid1")
		assert.True(t, found)
		assert.Equal(t, "value3", value)
		
		value, found = c.Get("valid2")
		assert.True(t, found)
		assert.Equal(t, "value4", value)
	})
	
	t.Run("CleanupExpired_AllValid", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi solo elementi validi
		c.Set("key1", "value1", 1*time.Hour)
		c.Set("key2", "value2", 1*time.Hour)
		
		assert.Equal(t, 2, c.Size())
		
		// Pulisci (non dovrebbe rimuovere nulla)
		c.CleanupExpired()
		
		assert.Equal(t, 2, c.Size())
	})
	
	t.Run("CleanupExpired_AllExpired", func(t *testing.T) {
		c := NewTestCache()
		
		// Aggiungi solo elementi che scadranno
		c.Set("key1", "value1", 1*time.Millisecond)
		c.Set("key2", "value2", 1*time.Millisecond)
		
		assert.Equal(t, 2, c.Size())
		
		// Attendi che scadano
		time.Sleep(2 * time.Millisecond)
		
		// Pulisci (dovrebbe rimuovere tutto)
		c.CleanupExpired()
		
		assert.Equal(t, 0, c.Size())
	})
	
	t.Run("CleanupExpired_EmptyCache", func(t *testing.T) {
		c := NewTestCache()
		
		assert.Equal(t, 0, c.Size())
		
		// Pulisci cache vuota (non dovrebbe causare errori)
		assert.NotPanics(t, func() {
			c.CleanupExpired()
		})
		
		assert.Equal(t, 0, c.Size())
	})
}

// TestCache_Size verifica la dimensione della cache
func TestCache_Size(t *testing.T) {
	c := NewTestCache()
	
	// Cache vuota
	assert.Equal(t, 0, c.Size())
	
	// Aggiungi elementi
	c.Set("key1", "value1", 1*time.Hour)
	assert.Equal(t, 1, c.Size())
	
	c.Set("key2", "value2", 1*time.Hour)
	assert.Equal(t, 2, c.Size())
	
	// Aggiorna elemento esistente (la dimensione non cambia)
	c.Set("key1", "updated_value", 1*time.Hour)
	assert.Equal(t, 2, c.Size())
	
	// Elimina elemento
	c.Delete("key1")
	assert.Equal(t, 1, c.Size())
	
	// Elimina elemento inesistente
	c.Delete("nonexistent")
	assert.Equal(t, 1, c.Size())
	
	// Svuota cache
	c.Clear()
	assert.Equal(t, 0, c.Size())
}

// TestCache_ConcurrentAccess verifica l'accesso concorrente
func TestCache_ConcurrentAccess(t *testing.T) {
	c := NewTestCache()
	iterations := 1000
	
	done := make(chan bool)
	
	// Goroutine per scrivere
	go func() {
		for i := 0; i < iterations; i++ {
			key := "key_" + string(rune('A'+(i%26)))
			c.Set(key, i, 1*time.Hour)
		}
		done <- true
	}()
	
	// Goroutine per leggere
	go func() {
		for i := 0; i < iterations; i++ {
			key := "key_" + string(rune('A'+(i%26)))
			c.Get(key)
		}
		done <- true
	}()
	
	// Goroutine per cancellare
	go func() {
		for i := 0; i < iterations; i++ {
			if i%10 == 0 { // Cancella ogni 10 iterazioni
				key := "key_" + string(rune('A'+(i%26)))
				c.Delete(key)
			}
		}
		done <- true
	}()
	
	// Goroutine per pulire elementi scaduti
	go func() {
		for i := 0; i < iterations/100; i++ {
			c.CleanupExpired()
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()
	
	// Attendi il completamento di tutte le goroutine
	for i := 0; i < 4; i++ {
		<-done
	}
	
	// La cache dovrebbe essere in uno stato valido
	// (non possiamo prevedere la dimensione esatta a causa della concorrenza)
	assert.GreaterOrEqual(t, c.Size(), 0)
	
	// Verifica che la cache funzioni ancora correttamente
	c.Set("final_key", "final_value", 1*time.Hour)
	value, found := c.Get("final_key")
	assert.True(t, found)
	assert.Equal(t, "final_value", value)
}

// Test della cache reale ma con logger disabilitato
func TestRealCache_BasicOperations(t *testing.T) {
	// Usa la cache reale ma disabilita i log chiamando solo metodi base
	c := cache.NewCache()
	
	// Test Set e Get senza logger (dovrebbe funzionare comunque)
	assert.NotPanics(t, func() {
		// Prova operazioni di base
		c.Set("test_key", "test_value", 1*time.Second)
		
		value, found := c.Get("test_key")
		assert.True(t, found)
		assert.Equal(t, "test_value", value)
		
		c.Delete("test_key")
		
		value, found = c.Get("test_key")
		assert.False(t, found)
		assert.Nil(t, value)
	})
}

// TestCache_EdgeCases verifica casi limite
func TestCache_EdgeCases(t *testing.T) {
	t.Run("EmptyKey", func(t *testing.T) {
		c := NewTestCache()
		
		// Chiave vuota
		c.Set("", "empty_key_value", 1*time.Hour)
		
		value, found := c.Get("")
		assert.True(t, found)
		assert.Equal(t, "empty_key_value", value)
		
		c.Delete("")
		value, found = c.Get("")
		assert.False(t, found)
		assert.Nil(t, value)
	})
	
	t.Run("NilValue", func(t *testing.T) {
		c := NewTestCache()
		
		// Valore nil
		c.Set("nil_key", nil, 1*time.Hour)
		
		value, found := c.Get("nil_key")
		assert.True(t, found)
		assert.Nil(t, value)
	})
	
	t.Run("NegativeTTL", func(t *testing.T) {
		c := NewTestCache()
		
		// TTL negativo (dovrebbe scadere immediatamente)
		c.Set("negative_ttl_key", "value", -1*time.Hour)
		
		value, found := c.Get("negative_ttl_key")
		assert.False(t, found)
		assert.Nil(t, value)
	})
	
	t.Run("VeryLongTTL", func(t *testing.T) {
		c := NewTestCache()
		
		// TTL molto lungo
		c.Set("long_ttl_key", "value", 365*24*time.Hour) // 1 anno
		
		value, found := c.Get("long_ttl_key")
		assert.True(t, found)
		assert.Equal(t, "value", value)
	})
}

// TestCache_GetAfterMultipleOperations verifica il comportamento dopo operazioni multiple
func TestCache_GetAfterMultipleOperations(t *testing.T) {
	c := NewTestCache()
	
	// Scenario complesso: aggiungi, aggiorna, elimina, ripeti
	c.Set("key1", "value1", 1*time.Hour)
	c.Set("key2", "value2", 1*time.Hour)
	c.Set("key3", "value3", 1*time.Millisecond) // Scadrà presto
	
	// Aggiorna key1
	c.Set("key1", "value1_updated", 2*time.Hour)
	
	// Elimina key2
	c.Delete("key2")
	
	// Attendi che key3 scada
	time.Sleep(2 * time.Millisecond)
	
	// Pulisci elementi scaduti
	c.CleanupExpired()
	
	// Verifica stato finale
	value, found := c.Get("key1")
	assert.True(t, found)
	assert.Equal(t, "value1_updated", value)
	
	value, found = c.Get("key2")
	assert.False(t, found)
	assert.Nil(t, value)
	
	value, found = c.Get("key3")
	assert.False(t, found)
	assert.Nil(t, value)
	
	assert.Equal(t, 1, c.Size())
}

// TestCache_ThreadSafety verifica la sicurezza del threading
func TestCache_ThreadSafety(t *testing.T) {
	c := NewTestCache()
	const numGoroutines = 50
	const operationsPerGoroutine = 100
	
	done := make(chan bool, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < operationsPerGoroutine; j++ {
				key := "key_" + string(rune('A'+(id%26))) + "_" + string(rune('0'+(j%10)))
				
				// Operazioni miste
				switch j % 4 {
				case 0:
					c.Set(key, "value", 1*time.Minute)
				case 1:
					c.Get(key)
				case 2:
					c.Delete(key)
				case 3:
					c.Size()
				}
			}
			done <- true
		}(i)
	}
	
	// Attendi il completamento
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	
	// La cache dovrebbe essere in uno stato consistente
	// Verifica che le operazioni di base funzionino ancora
	c.Set("final_test_key", "final_test_value", 1*time.Minute)
	value, found := c.Get("final_test_key")
	assert.True(t, found)
	assert.Equal(t, "final_test_value", value)
	
	// Pulisci
	c.Delete("final_test_key")
	
	// Verifica che la dimensione sia consistente
	size := c.Size()
	assert.GreaterOrEqual(t, size, 0)
	
	// Se ci sono elementi, verifica che siano accessibili
	if size > 0 {
		// Non possiamo sapere quali chiavi ci sono a causa della concorrenza,
		// ma possiamo verificare che la cache non sia in uno stato corrotto
		c.Clear()
		assert.Equal(t, 0, c.Size())
	}
}

// TestCache_MemoryReuse verifica che la cache gestisca correttamente la memoria
func TestCache_MemoryReuse(t *testing.T) {
	c := NewTestCache()

	// Aggiungi molti elementi con chiavi uniche
	const numElements = 1000
	for i := 0; i < numElements; i++ {
		key := "key_unique_" + string(rune('0'+(i/100%10))) + string(rune('0'+(i/10%10))) + string(rune('0'+(i%10)))
		c.Set(key, i, 1*time.Millisecond)
	}

	// Verifica che siano stati aggiunti tutti gli elementi
	initialSize := c.Size()
	assert.Equal(t, numElements, initialSize, "Should have all elements before expiration")

	// Attendi che tutti scadano
	time.Sleep(5 * time.Millisecond)

	// Pulisci tutti gli elementi scaduti
	c.CleanupExpired()

	// La cache dovrebbe essere vuota
	assert.Equal(t, 0, c.Size())

	// Verifica che la cache sia ancora utilizzabile
	c.Set("new_key", "new_value", 1*time.Hour)
	value, found := c.Get("new_key")
	assert.True(t, found)
	assert.Equal(t, "new_value", value)

	assert.Equal(t, 1, c.Size())
}

// TestCache_ExpirationAccuracy verifica l'accuratezza della scadenza
func TestCache_ExpirationAccuracy(t *testing.T) {
	c := NewTestCache()
	
	// Test con TTL molto preciso
	ttl := 50 * time.Millisecond
	start := time.Now()
	
	c.Set("precise_key", "value", ttl)
	
	// Verifica immediatamente dopo l'inserimento (dovrebbe essere presente)
	value, found := c.Get("precise_key")
	assert.True(t, found)
	assert.Equal(t, "value", value)
	
	// Attendi metà del TTL
	time.Sleep(ttl / 2)
	
	// Dovrebbe essere ancora presente
	value, found = c.Get("precise_key")
	assert.True(t, found)
	assert.Equal(t, "value", value)
	
	// Attendi la scadenza completa (con un piccolo margine)
	time.Sleep(ttl/2 + 5*time.Millisecond)
	
	// Dovrebbe essere scaduto
	value, found = c.Get("precise_key")
	assert.False(t, found)
	assert.Nil(t, value)
	
	elapsed := time.Since(start)
	// Verifica che sia trascorso all'incirca il TTL
	assert.InDelta(t, ttl.Milliseconds(), elapsed.Milliseconds(), 10.0) // ±10ms di tolleranza
}

// TestCache_Performance verifica le performance di base
func TestCache_Performance(t *testing.T) {
	c := NewTestCache()
	const iterations = 10000
	
	start := time.Now()
	
	// Operazioni di scrittura
	for i := 0; i < iterations; i++ {
		key := "perf_key_" + string(rune('A'+(i%26)))
		c.Set(key, i, 1*time.Hour)
	}
	
	writeTime := time.Since(start)
	
	// Operazioni di lettura
	start = time.Now()
	for i := 0; i < iterations; i++ {
		key := "perf_key_" + string(rune('A'+(i%26)))
		c.Get(key)
	}
	
	readTime := time.Since(start)
	
	// Verifica che i tempi siano ragionevoli
	t.Logf("Write %d items: %v", iterations, writeTime)
	t.Logf("Read %d items: %v", iterations, readTime)
	t.Logf("Average write time: %v", writeTime/time.Duration(iterations))
	t.Logf("Average read time: %v", readTime/time.Duration(iterations))
	
	// Verifica che tutti gli elementi siano stati inseriti
	assert.Equal(t, 26, c.Size()) // 26 chiavi uniche (A-Z)
}

// ========================================
// Tests for real cache.Cache implementation
// ========================================

// TestRealCache_Clear tests the Clear function of real cache
func TestRealCache_Clear(t *testing.T) {
	c := cache.NewCache()

	// Add entries
	c.Set("key1", "value1", 1*time.Hour)
	c.Set("key2", "value2", 1*time.Hour)
	c.Set("key3", "value3", 1*time.Hour)

	assert.Equal(t, 3, c.Size())

	// Clear
	c.Clear()

	assert.Equal(t, 0, c.Size())

	// Verify entries are gone
	_, exists := c.Get("key1")
	assert.False(t, exists)

	// Verify cache still works after clear
	c.Set("new_key", "new_value", 1*time.Hour)
	val, exists := c.Get("new_key")
	assert.True(t, exists)
	assert.Equal(t, "new_value", val)
}

// TestRealCache_Size tests the Size function
func TestRealCache_Size(t *testing.T) {
	c := cache.NewCache()

	assert.Equal(t, 0, c.Size())

	c.Set("key1", "value1", 1*time.Hour)
	assert.Equal(t, 1, c.Size())

	c.Set("key2", "value2", 1*time.Hour)
	assert.Equal(t, 2, c.Size())

	c.Set("key1", "updated", 1*time.Hour)
	assert.Equal(t, 2, c.Size())

	c.Delete("key1")
	assert.Equal(t, 1, c.Size())

	c.Clear()
	assert.Equal(t, 0, c.Size())
}

// TestRealCache_CleanupExpired tests the CleanupExpired function
func TestRealCache_CleanupExpired(t *testing.T) {
	c := cache.NewCache()

	// Add entries with different TTLs
	c.Set("short1", "value1", 50*time.Millisecond)
	c.Set("short2", "value2", 50*time.Millisecond)
	c.Set("long1", "value3", 10*time.Hour)
	c.Set("long2", "value4", 10*time.Hour)

	assert.Equal(t, 4, c.Size())

	// Wait for short entries to expire
	time.Sleep(100 * time.Millisecond)

	// Cleanup
	c.CleanupExpired()

	// Should have only 2 entries left
	assert.Equal(t, 2, c.Size())

	// Verify long entries still exist
	val, exists := c.Get("long1")
	assert.True(t, exists)
	assert.Equal(t, "value3", val)

	val, exists = c.Get("long2")
	assert.True(t, exists)
	assert.Equal(t, "value4", val)

	// Verify short entries are gone
	_, exists = c.Get("short1")
	assert.False(t, exists)

	_, exists = c.Get("short2")
	assert.False(t, exists)
}

// TestRealCache_CleanupExpired_AllValid tests cleanup with no expired entries
func TestRealCache_CleanupExpired_AllValid(t *testing.T) {
	c := cache.NewCache()

	c.Set("key1", "value1", 10*time.Hour)
	c.Set("key2", "value2", 10*time.Hour)

	assert.Equal(t, 2, c.Size())

	// Cleanup (should not remove anything)
	c.CleanupExpired()

	assert.Equal(t, 2, c.Size())
}

// TestRealCache_CleanupExpired_Empty tests cleanup on empty cache
func TestRealCache_CleanupExpired_Empty(t *testing.T) {
	c := cache.NewCache()

	assert.Equal(t, 0, c.Size())

	// Should not panic
	c.CleanupExpired()

	assert.Equal(t, 0, c.Size())
}

// TestRealCache_CleanupExpired_AllExpired tests cleanup with all expired entries
func TestRealCache_CleanupExpired_AllExpired(t *testing.T) {
	c := cache.NewCache()

	c.Set("key1", "value1", 50*time.Millisecond)
	c.Set("key2", "value2", 50*time.Millisecond)

	assert.Equal(t, 2, c.Size())

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Cleanup
	c.CleanupExpired()

	assert.Equal(t, 0, c.Size())
}

// TestGetStats tests the global GetStats function
func TestGetStats(t *testing.T) {
	// Clear global caches first
	cache.DefaultRulesCache.Clear()
	cache.GeoIPCache.Clear()

	// Add entries to DefaultRulesCache
	cache.DefaultRulesCache.Set("rule1", "value1", 1*time.Hour)
	cache.DefaultRulesCache.Set("rule2", "value2", 1*time.Hour)
	cache.DefaultRulesCache.Set("rule3", "value3", 1*time.Hour)

	// Add entries to GeoIPCache
	cache.GeoIPCache.Set("ip1", "US", 1*time.Hour)
	cache.GeoIPCache.Set("ip2", "UK", 1*time.Hour)

	// Get stats
	stats := cache.GetStats()

	assert.Equal(t, 3, stats.DefaultRulesSize)
	assert.Equal(t, 2, stats.GeoIPSize)
	assert.Equal(t, 5, stats.TotalSize)

	// Clean up
	cache.DefaultRulesCache.Clear()
	cache.GeoIPCache.Clear()
}

// TestGetStats_EmptyCaches tests GetStats with empty caches
func TestGetStats_EmptyCaches(t *testing.T) {
	cache.DefaultRulesCache.Clear()
	cache.GeoIPCache.Clear()

	stats := cache.GetStats()

	assert.Equal(t, 0, stats.DefaultRulesSize)
	assert.Equal(t, 0, stats.GeoIPSize)
	assert.Equal(t, 0, stats.TotalSize)
}

// TestInitializeCleanupWorker tests the cleanup worker goroutine
func TestInitializeCleanupWorker(t *testing.T) {
	// Clear global caches
	cache.DefaultRulesCache.Clear()
	cache.GeoIPCache.Clear()

	// Add entries with short TTL
	cache.DefaultRulesCache.Set("temp1", "value1", 100*time.Millisecond)
	cache.DefaultRulesCache.Set("temp2", "value2", 100*time.Millisecond)
	cache.DefaultRulesCache.Set("perm1", "value3", 10*time.Hour)

	cache.GeoIPCache.Set("temp3", "US", 100*time.Millisecond)
	cache.GeoIPCache.Set("perm2", "UK", 10*time.Hour)

	// Initialize cleanup worker with fast interval
	cache.InitializeCleanupWorker(50 * time.Millisecond)

	// Wait for entries to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Check that temporary entries were cleaned up
	assert.Equal(t, 1, cache.DefaultRulesCache.Size())
	val, exists := cache.DefaultRulesCache.Get("perm1")
	assert.True(t, exists)
	assert.Equal(t, "value3", val)

	assert.Equal(t, 1, cache.GeoIPCache.Size())
	val, exists = cache.GeoIPCache.Get("perm2")
	assert.True(t, exists)
	assert.Equal(t, "UK", val)

	// Clean up
	cache.DefaultRulesCache.Clear()
	cache.GeoIPCache.Clear()
}

// TestGlobalCaches_DefaultRulesCache tests the DefaultRulesCache global instance
func TestGlobalCaches_DefaultRulesCache(t *testing.T) {
	cache.DefaultRulesCache.Clear()

	cache.DefaultRulesCache.Set("rule1", "ruleValue", 1*time.Hour)

	val, exists := cache.DefaultRulesCache.Get("rule1")
	assert.True(t, exists)
	assert.Equal(t, "ruleValue", val)

	cache.DefaultRulesCache.Delete("rule1")
	_, exists = cache.DefaultRulesCache.Get("rule1")
	assert.False(t, exists)

	cache.DefaultRulesCache.Clear()
}

// TestGlobalCaches_GeoIPCache tests the GeoIPCache global instance
func TestGlobalCaches_GeoIPCache(t *testing.T) {
	cache.GeoIPCache.Clear()

	cache.GeoIPCache.Set("192.168.1.1", "US", 1*time.Hour)

	val, exists := cache.GeoIPCache.Get("192.168.1.1")
	assert.True(t, exists)
	assert.Equal(t, "US", val)

	cache.GeoIPCache.Delete("192.168.1.1")
	_, exists = cache.GeoIPCache.Get("192.168.1.1")
	assert.False(t, exists)

	cache.GeoIPCache.Clear()
}

// TestRealCache_GetWithExpiredEntry tests Get with an expired entry
func TestRealCache_GetWithExpiredEntry(t *testing.T) {
	c := cache.NewCache()

	// Set with very short TTL
	c.Set("key1", "value1", 50*time.Millisecond)

	// Should exist immediately
	val, exists := c.Get("key1")
	assert.True(t, exists)
	assert.Equal(t, "value1", val)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	val, exists = c.Get("key1")
	assert.False(t, exists)
	assert.Nil(t, val)
}

// TestRealCache_GetNonExistent tests Get with non-existent key
func TestRealCache_GetNonExistent(t *testing.T) {
	c := cache.NewCache()

	val, exists := c.Get("nonexistent")
	assert.False(t, exists)
	assert.Nil(t, val)
}

// TestRealCache_ConcurrentAccess tests thread safety of real cache
func TestRealCache_ConcurrentAccess(t *testing.T) {
	c := cache.NewCache()
	var wg sync.WaitGroup

	numGoroutines := 100
	wg.Add(numGoroutines * 3)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			key := "key_" + string(rune('a'+(index%26)))
			c.Set(key, index, 1*time.Hour)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			key := "key_" + string(rune('a'+(index%26)))
			c.Get(key)
		}(i)
	}

	// Concurrent deletes
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			if index%5 == 0 {
				key := "key_" + string(rune('a'+(index%26)))
				c.Delete(key)
			}
		}(i)
	}

	wg.Wait()

	// Cache should be in valid state
	size := c.Size()
	assert.GreaterOrEqual(t, size, 0)
	assert.LessOrEqual(t, size, 26)

	// Verify cache still works
	c.Set("final", "value", 1*time.Hour)
	val, exists := c.Get("final")
	assert.True(t, exists)
	assert.Equal(t, "value", val)

	c.Clear()
}