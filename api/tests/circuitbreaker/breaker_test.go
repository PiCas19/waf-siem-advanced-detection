package circuitbreaker

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/circuitbreaker"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// init initializes the logger for tests
func init() {
	if err := logger.InitLogger("error", "stdout"); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
}

// TestNewCircuitBreaker tests circuit breaker creation
func TestNewCircuitBreaker(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 5, 10*time.Second)
	
	require.NotNil(t, cb)
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
}

// TestCircuitBreaker_Call_Success tests successful calls
func TestCircuitBreaker_Call_Success(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 3, 5*time.Second)
	
	// Successful call
	err := cb.Call(func() error {
		return nil
	})
	
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
}

// TestCircuitBreaker_Call_Failure tests failed calls
func TestCircuitBreaker_Call_Failure(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 3, 5*time.Second)
	
	testErr := errors.New("test error")
	
	// Single failure
	err := cb.Call(func() error {
		return testErr
	})
	
	assert.Error(t, err)
	assert.Equal(t, testErr, err)
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
}

// TestCircuitBreaker_Call_MultipleFailures tests circuit opening after max failures
func TestCircuitBreaker_Call_MultipleFailures(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 3, 5*time.Second)
	
	testErr := errors.New("test error")
	
	// First failure
	err := cb.Call(func() error {
		return testErr
	})
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Second failure
	err = cb.Call(func() error {
		return testErr
	})
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Third failure - should open circuit
	err = cb.Call(func() error {
		return testErr
	})
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_Call_OpenState tests calls when circuit is open
func TestCircuitBreaker_Call_OpenState(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 100*time.Millisecond)
	
	testErr := errors.New("test error")
	
	// Trigger failures to open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	
	// Circuit should be open
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Next call should fail with ErrCircuitOpen
	err := cb.Call(func() error {
		return nil // This should not be called
	})
	
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.ErrCircuitOpen, err)
}

// TestCircuitBreaker_Call_HalfOpenTransition tests transition from Open to HalfOpen
func TestCircuitBreaker_Call_HalfOpenTransition(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 50*time.Millisecond)
	
	testErr := errors.New("test error")
	
	// Open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Wait for reset timeout
	time.Sleep(100 * time.Millisecond)
	
	// Next call should transition to HalfOpen
	err := cb.Call(func() error {
		return nil
	})
	
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.HalfOpen, cb.GetState())
}

// TestCircuitBreaker_Call_HalfOpenRecovery tests recovery from HalfOpen to Closed
func TestCircuitBreaker_Call_HalfOpenRecovery(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 50*time.Millisecond)
	
	testErr := errors.New("test error")
	
	// Open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Wait for reset timeout
	time.Sleep(100 * time.Millisecond)
	
	// First successful call - transitions to HalfOpen
	err := cb.Call(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.HalfOpen, cb.GetState())
	
	// Second successful call - still HalfOpen
	err = cb.Call(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.HalfOpen, cb.GetState())
	
	// Third successful call - should transition to Closed
	err = cb.Call(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
}

// TestCircuitBreaker_Call_HalfOpenFailure tests failure in HalfOpen state
func TestCircuitBreaker_Call_HalfOpenFailure(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 50*time.Millisecond)
	
	testErr := errors.New("test error")
	
	// Open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Wait for reset timeout
	time.Sleep(100 * time.Millisecond)
	
	// First call succeeds - transitions to HalfOpen
	err := cb.Call(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.HalfOpen, cb.GetState())
	
	// Second call fails - should open again
	err = cb.Call(func() error { return testErr })
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_GetState tests state retrieval
func TestCircuitBreaker_GetState(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 1, 5*time.Second)
	
	// Initial state
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Open circuit
	cb.Call(func() error { return errors.New("error") })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_Reset tests circuit reset
func TestCircuitBreaker_Reset(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 5*time.Second)
	
	testErr := errors.New("test error")
	
	// Open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Reset
	cb.Reset()
	
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Should work normally after reset
	err := cb.Call(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
}

// TestCircuitBreaker_Reset_ClearsCounters tests reset clears all counters
func TestCircuitBreaker_Reset_ClearsCounters(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 3, 5*time.Second)
	
	testErr := errors.New("test error")
	
	// Record some failures
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Reset
	cb.Reset()
	
	// Should be able to handle maxFailures again before opening
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestState_String tests state string representation
func TestState_String(t *testing.T) {
	assert.Equal(t, "Closed", circuitbreaker.Closed.String())
	assert.Equal(t, "Open", circuitbreaker.Open.String())
	assert.Equal(t, "HalfOpen", circuitbreaker.HalfOpen.String())
	
	// Test unknown state
	var unknownState circuitbreaker.State = 99
	assert.Equal(t, "Unknown", unknownState.String())
}

// TestCircuitBreaker_ConcurrentCalls tests thread safety
func TestCircuitBreaker_ConcurrentCalls(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 10, 1*time.Second)
	
	var wg sync.WaitGroup
	numGoroutines := 100
	
	wg.Add(numGoroutines * 2)
	
	// Concurrent successful calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			cb.Call(func() error {
				return nil
			})
		}()
	}
	
	// Concurrent failed calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			cb.Call(func() error {
				return errors.New("error")
			})
		}()
	}
	
	wg.Wait()
	
	// Circuit should be in some valid state
	state := cb.GetState()
	assert.True(t, state == circuitbreaker.Closed || state == circuitbreaker.Open || state == circuitbreaker.HalfOpen)
}

// TestCircuitBreaker_ConcurrentGetState tests concurrent state reads
func TestCircuitBreaker_ConcurrentGetState(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 5, 1*time.Second)
	
	var wg sync.WaitGroup
	numGoroutines := 100
	
	wg.Add(numGoroutines * 2)
	
	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			cb.GetState()
		}()
	}
	
	// Concurrent writes (calls)
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			if index%2 == 0 {
				cb.Call(func() error { return nil })
			} else {
				cb.Call(func() error { return errors.New("error") })
			}
		}(i)
	}
	
	wg.Wait()
	
	// Should not panic
	assert.NotPanics(t, func() {
		cb.GetState()
	})
}

// TestCircuitBreaker_ConcurrentReset tests concurrent resets
func TestCircuitBreaker_ConcurrentReset(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 5, 1*time.Second)
	
	var wg sync.WaitGroup
	numGoroutines := 50
	
	wg.Add(numGoroutines * 3)
	
	// Concurrent calls
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			if index%2 == 0 {
				cb.Call(func() error { return nil })
			} else {
				cb.Call(func() error { return errors.New("error") })
			}
		}(i)
	}
	
	// Concurrent resets
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			cb.Reset()
		}()
	}
	
	// Concurrent state reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			cb.GetState()
		}()
	}
	
	wg.Wait()
	
	// Circuit should be in valid state
	state := cb.GetState()
	assert.True(t, state == circuitbreaker.Closed || state == circuitbreaker.Open || state == circuitbreaker.HalfOpen)
}

// TestCircuitBreaker_SuccessResetsFailures tests success resets failure counter in Closed state
func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 3, 5*time.Second)
	
	testErr := errors.New("test error")
	
	// Record some failures
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Successful call should reset counter
	cb.Call(func() error { return nil })
	
	// Should be able to handle 3 more failures before opening
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_MultipleRecoveries tests multiple recovery cycles
func TestCircuitBreaker_MultipleRecoveries(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 50*time.Millisecond)
	
	testErr := errors.New("test error")
	
	// First cycle: Open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Wait and recover
	time.Sleep(100 * time.Millisecond)
	cb.Call(func() error { return nil })
	cb.Call(func() error { return nil })
	cb.Call(func() error { return nil })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Second cycle: Open circuit again
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Wait and recover again
	time.Sleep(100 * time.Millisecond)
	cb.Call(func() error { return nil })
	cb.Call(func() error { return nil })
	cb.Call(func() error { return nil })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
}

// TestCircuitBreaker_ZeroMaxFailures tests circuit with zero max failures
func TestCircuitBreaker_ZeroMaxFailures(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 0, 5*time.Second)
	
	// Should open immediately on first failure
	err := cb.Call(func() error {
		return errors.New("error")
	})
	
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_VeryShortResetTimeout tests very short reset timeout
func TestCircuitBreaker_VeryShortResetTimeout(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 10*time.Millisecond)
	
	testErr := errors.New("test error")
	
	// Open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Wait for reset timeout
	time.Sleep(20 * time.Millisecond)
	
	// Should transition to HalfOpen
	err := cb.Call(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.HalfOpen, cb.GetState())
}

// TestCircuitBreaker_VeryLongResetTimeout tests very long reset timeout
func TestCircuitBreaker_VeryLongResetTimeout(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 2, 10*time.Hour)
	
	testErr := errors.New("test error")
	
	// Open circuit
	cb.Call(func() error { return testErr })
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	// Wait a short time (much less than reset timeout)
	time.Sleep(50 * time.Millisecond)
	
	// Should still be Open
	err := cb.Call(func() error { return nil })
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.ErrCircuitOpen, err)
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_ExactlyAtMaxFailures tests behavior at exactly max failures
func TestCircuitBreaker_ExactlyAtMaxFailures(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 3, 5*time.Second)
	
	testErr := errors.New("test error")
	
	// Failure 1
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Failure 2
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// Failure 3 - should open
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_NamePreservation tests that name is preserved
func TestCircuitBreaker_NamePreservation(t *testing.T) {
	cb1 := circuitbreaker.NewCircuitBreaker("breaker1", 5, 5*time.Second)
	cb2 := circuitbreaker.NewCircuitBreaker("breaker2", 5, 5*time.Second)
	
	// Both should be independent
	require.NotNil(t, cb1)
	require.NotNil(t, cb2)
	
	// Open cb1
	testErr := errors.New("error")
	for i := 0; i < 5; i++ {
		cb1.Call(func() error { return testErr })
	}
	
	assert.Equal(t, circuitbreaker.Open, cb1.GetState())
	assert.Equal(t, circuitbreaker.Closed, cb2.GetState())
}

// TestCircuitBreaker_QuickSuccessionCalls tests many calls in quick succession
func TestCircuitBreaker_QuickSuccessionCalls(t *testing.T) {
	cb := circuitbreaker.NewCircuitBreaker("test", 10, 1*time.Second)
	
	// 20 successful calls in quick succession
	for i := 0; i < 20; i++ {
		err := cb.Call(func() error { return nil })
		assert.NoError(t, err)
	}
	
	assert.Equal(t, circuitbreaker.Closed, cb.GetState())
	
	// 10 failed calls - should open
	for i := 0; i < 10; i++ {
		cb.Call(func() error { return errors.New("error") })
	}
	
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
}

// TestCircuitBreaker_OpenDuration tests that circuit stays open for the expected duration
func TestCircuitBreaker_OpenDuration(t *testing.T) {
	resetTimeout := 100 * time.Millisecond
	cb := circuitbreaker.NewCircuitBreaker("test", 1, resetTimeout)
	
	testErr := errors.New("test error")
	
	// Open circuit
	cb.Call(func() error { return testErr })
	assert.Equal(t, circuitbreaker.Open, cb.GetState())
	
	startTime := time.Now()
	
	// Try to call before reset timeout - should fail
	time.Sleep(50 * time.Millisecond)
	err := cb.Call(func() error { return nil })
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.ErrCircuitOpen, err)
	
	// Wait until after reset timeout
	time.Sleep(100 * time.Millisecond)
	
	// Should transition to HalfOpen
	err = cb.Call(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.HalfOpen, cb.GetState())
	
	elapsed := time.Since(startTime)
	assert.GreaterOrEqual(t, elapsed, resetTimeout)
}
