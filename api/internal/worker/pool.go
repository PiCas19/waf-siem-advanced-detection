package worker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// Job represents a unit of work to be processed
type Job interface {
	Execute(ctx context.Context) error
	ID() string
}

// EnrichmentJob represents a threat intelligence enrichment task
type EnrichmentJob struct {
	id       string
	logID    uint
	ip       string
	onResult func(result interface{}, err error)
}

func NewEnrichmentJob(id string, logID uint, ip string, onResult func(interface{}, error)) Job {
	return &EnrichmentJob{
		id:       id,
		logID:    logID,
		ip:       ip,
		onResult: onResult,
	}
}

func (j *EnrichmentJob) ID() string {
	return j.id
}

func (j *EnrichmentJob) Execute(ctx context.Context) error {
	// Implementation will be provided by the worker
	return nil
}

// EmailJob represents an email sending task
type EmailJob struct {
	id        string
	toEmail   string
	subject   string
	htmlBody  string
	onResult  func(error)
}

func NewEmailJob(id string, toEmail string, subject string, htmlBody string, onResult func(error)) Job {
	return &EmailJob{
		id:       id,
		toEmail:  toEmail,
		subject:  subject,
		htmlBody: htmlBody,
		onResult: onResult,
	}
}

func (j *EmailJob) ID() string {
	return j.id
}

func (j *EmailJob) Execute(ctx context.Context) error {
	return nil // Implementation provided by worker
}

// Worker processes jobs from a queue
type Worker struct {
	id       int
	jobChan  chan Job
	resultCh chan WorkerResult
	done     chan struct{}
	executor JobExecutor
}

// JobExecutor executes a job
type JobExecutor interface {
	Execute(ctx context.Context, job Job) error
}

// WorkerResult represents the result of a job execution
type WorkerResult struct {
	JobID string
	Err   error
	Time  time.Duration
}

// NewWorker creates a new worker
func NewWorker(id int, jobChan chan Job, resultCh chan WorkerResult, executor JobExecutor) *Worker {
	return &Worker{
		id:       id,
		jobChan:  jobChan,
		resultCh: resultCh,
		done:     make(chan struct{}),
		executor: executor,
	}
}

// Start begins processing jobs
func (w *Worker) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-w.done:
				logger.Log.WithField("worker_id", w.id).Info("Worker shutting down")
				return
			case <-ctx.Done():
				logger.Log.WithField("worker_id", w.id).Info("Worker context cancelled")
				return
			case job := <-w.jobChan:
				if job == nil {
					return
				}
				start := time.Now()
				err := w.executor.Execute(ctx, job)
				duration := time.Since(start)

				w.resultCh <- WorkerResult{
					JobID: job.ID(),
					Err:   err,
					Time:  duration,
				}

				if err != nil {
					logger.Log.WithFields(map[string]interface{}{
						"worker_id": w.id,
						"job_id":    job.ID(),
						"duration":  duration,
					}).WithError(err).Error("Job failed")
				} else {
					logger.Log.WithFields(map[string]interface{}{
						"worker_id": w.id,
						"job_id":    job.ID(),
						"duration":  duration,
					}).Info("Job completed")
				}
			}
		}
	}()
}

// Stop stops the worker
func (w *Worker) Stop() {
	close(w.done)
}

// WorkerPool manages multiple workers
type WorkerPool struct {
	workers       []*Worker
	jobChan       chan Job
	resultCh      chan WorkerResult
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	stats         PoolStats
	done          chan struct{}
}

// PoolStats tracks pool statistics
type PoolStats struct {
	JobsProcessed  int64
	JobsFailed     int64
	TotalJobTime   time.Duration
	AvgJobTime     time.Duration
	mu             sync.RWMutex
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers int, queueSize int, executor JobExecutor) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers:  make([]*Worker, numWorkers),
		jobChan:  make(chan Job, queueSize),
		resultCh: make(chan WorkerResult, queueSize),
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}

	// Create workers
	for i := 0; i < numWorkers; i++ {
		pool.workers[i] = NewWorker(i+1, pool.jobChan, pool.resultCh, executor)
		pool.workers[i].Start(ctx)
	}

	// Result processor goroutine
	go pool.processResults()

	return pool
}

// Submit submits a job to the pool
func (p *WorkerPool) Submit(job Job) error {
	select {
	case p.jobChan <- job:
		return nil
	case <-p.ctx.Done():
		return fmt.Errorf("pool is shutting down")
	default:
		return fmt.Errorf("job queue is full")
	}
}

// SubmitAsync submits a job and returns immediately
func (p *WorkerPool) SubmitAsync(job Job) <-chan WorkerResult {
	resultCh := make(chan WorkerResult, 1)
	go func() {
		if err := p.Submit(job); err != nil {
			resultCh <- WorkerResult{
				JobID: job.ID(),
				Err:   err,
			}
		}
	}()
	return resultCh
}

// processResults handles job completion results
func (p *WorkerPool) processResults() {
	for {
		select {
		case <-p.done:
			return
		case result := <-p.resultCh:
			p.mu.Lock()
			p.stats.JobsProcessed++
			p.stats.TotalJobTime += result.Time
			if result.Err != nil {
				p.stats.JobsFailed++
			}
			p.stats.AvgJobTime = p.stats.TotalJobTime / time.Duration(p.stats.JobsProcessed)
			p.mu.Unlock()
		}
	}
}

// GetStats returns current pool statistics
func (p *WorkerPool) GetStats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// Shutdown gracefully shuts down the pool
func (p *WorkerPool) Shutdown(timeout time.Duration) error {
	logger.Log.Info("WorkerPool initiating shutdown")

	// Stop accepting new jobs
	close(p.jobChan)

	// Wait for all workers to finish or timeout
	done := make(chan struct{})
	go func() {
		for _, worker := range p.workers {
			worker.Stop()
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
		logger.Log.Info("WorkerPool all workers shut down successfully")
	case <-time.After(timeout):
		logger.Log.Warn("WorkerPool shutdown timeout - forcing termination")
	}

	p.cancel()
	close(p.done)
	return nil
}

// QueueSize returns current job queue size
func (p *WorkerPool) QueueSize() int {
	return len(p.jobChan)
}

// NumWorkers returns number of workers in the pool
func (p *WorkerPool) NumWorkers() int {
	return len(p.workers)
}
