package circuitbreaker

import (
	"errors"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// State rappresenta lo stato del circuit breaker
type State int

const (
	// Closed: circuito funziona normalmente
	Closed State = iota
	// Open: circuito è aperto, rifiuta tutte le richieste
	Open
	// HalfOpen: circuito sta verificando se il servizio è tornato online
	HalfOpen
)

// CircuitBreaker implementa il pattern circuit breaker
type CircuitBreaker struct {
	name             string
	maxFailures      int
	resetTimeout     time.Duration
	halfOpenRequests int

	mu              sync.RWMutex
	state           State
	failures        int
	lastFailureTime time.Time
	successCount    int
}

// ErrCircuitOpen indica che il circuito è aperto
var ErrCircuitOpen = errors.New("circuit breaker is open")

// ErrCircuitHalfOpen indica che il circuito è in half-open
var ErrCircuitHalfOpen = errors.New("circuit breaker is half-open")

// NewCircuitBreaker crea un nuovo circuit breaker
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:             name,
		maxFailures:      maxFailures,
		resetTimeout:     resetTimeout,
		halfOpenRequests: 3, // Numero di richieste riuscite per chiudere il circuito
		state:            Closed,
		failures:         0,
	}
}

// Call esegue una funzione con protezione del circuit breaker
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Verifica lo stato attuale
	if cb.state == Open {
		// Controlla se è il momento di passare a half-open
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.transitionToHalfOpen()
		} else {
			logger.WithFields(map[string]interface{}{
				"circuit_breaker": cb.name,
				"state":           "open",
			}).Warn("Circuit breaker is open, rejecting request")
			return ErrCircuitOpen
		}
	}

	// Esegui la funzione
	err := fn()

	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// recordFailure registra un fallimento
func (cb *CircuitBreaker) recordFailure() {
	cb.failures++
	cb.lastFailureTime = time.Now()

	logger.WithFields(map[string]interface{}{
		"circuit_breaker": cb.name,
		"failures":        cb.failures,
		"max_failures":    cb.maxFailures,
	}).Warn("Circuit breaker recorded failure")

	if cb.failures >= cb.maxFailures {
		cb.transitionToOpen()
	}
}

// recordSuccess registra un successo
func (cb *CircuitBreaker) recordSuccess() {
	if cb.state == HalfOpen {
		cb.successCount++

		if cb.successCount >= cb.halfOpenRequests {
			cb.transitionToClosed()
		}
	} else if cb.state == Closed {
		// Reset contatori su successo in stato closed
		cb.failures = 0
		cb.successCount = 0
	}
}

// transitionToOpen sposta lo stato a Open
func (cb *CircuitBreaker) transitionToOpen() {
	cb.state = Open
	logger.WithFields(map[string]interface{}{
		"circuit_breaker": cb.name,
		"state":           "open",
	}).Error("Circuit breaker opened, rejecting requests")
}

// transitionToHalfOpen sposta lo stato a HalfOpen
func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.state = HalfOpen
	cb.successCount = 0
	logger.WithFields(map[string]interface{}{
		"circuit_breaker": cb.name,
		"state":           "half-open",
	}).Info("Circuit breaker half-opened, trying to recover")
}

// transitionToClosed sposta lo stato a Closed
func (cb *CircuitBreaker) transitionToClosed() {
	cb.state = Closed
	cb.failures = 0
	cb.successCount = 0
	logger.WithFields(map[string]interface{}{
		"circuit_breaker": cb.name,
		"state":           "closed",
	}).Info("Circuit breaker closed, normal operation resumed")
}

// GetState ritorna lo stato attuale
func (cb *CircuitBreaker) GetState() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset resetta il circuit breaker
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = Closed
	cb.failures = 0
	cb.successCount = 0
	cb.lastFailureTime = time.Time{}
	logger.WithFields(map[string]interface{}{
		"circuit_breaker": cb.name,
	}).Info("Circuit breaker reset")
}

// String ritorna una rappresentazione string dello stato
func (s State) String() string {
	switch s {
	case Closed:
		return "Closed"
	case Open:
		return "Open"
	case HalfOpen:
		return "HalfOpen"
	default:
		return "Unknown"
	}
}
