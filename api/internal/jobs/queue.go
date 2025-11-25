package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// JobType defines the type of job
type JobType string

const (
	JobTypeEmailNotification JobType = "email_notification"
	JobTypeDataExport       JobType = "data_export"
	JobTypeReportGeneration JobType = "report_generation"
	JobTypeCleanup          JobType = "cleanup"
	JobTypeSync             JobType = "sync"
)

// JobStatus defines the status of a job
type JobStatus string

const (
	StatusPending   JobStatus = "pending"
	StatusRunning   JobStatus = "running"
	StatusCompleted JobStatus = "completed"
	StatusFailed    JobStatus = "failed"
	StatusRetrying  JobStatus = "retrying"
)

// Job represents an async job
type Job struct {
	ID          string                 `json:"id"`
	Type        JobType                `json:"type"`
	Status      JobStatus              `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Data        map[string]interface{} `json:"data"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Retries     int                    `json:"retries"`
	MaxRetries  int                    `json:"max_retries"`
}

// JobHandler is a function that handles a job
type JobHandler func(ctx context.Context, job *Job) error

// Queue manages async jobs with retry logic
type Queue struct {
	jobs      map[string]*Job
	handlers  map[JobType]JobHandler
	mu        sync.RWMutex
	workChan  chan *Job
	workers   int
	maxRetries int
}

// NewQueue creates a new job queue with specified workers
func NewQueue(workers int, maxRetries int) *Queue {
	queue := &Queue{
		jobs:       make(map[string]*Job),
		handlers:   make(map[JobType]JobHandler),
		workChan:   make(chan *Job, workers*2),
		workers:    workers,
		maxRetries: maxRetries,
	}

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		go queue.worker(i)
	}

	logger.Log.WithFields(map[string]interface{}{
		"action":  "job_queue_started",
		"workers": workers,
	}).Info("Job queue initialized")

	return queue
}

// RegisterHandler registers a job handler for a specific job type
func (q *Queue) RegisterHandler(jobType JobType, handler JobHandler) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.handlers[jobType] = handler
	logger.Log.WithFields(map[string]interface{}{
		"action":   "handler_registered",
		"job_type": jobType,
	}).Debug("Job handler registered")
}

// Enqueue adds a job to the queue
func (q *Queue) Enqueue(jobType JobType, data map[string]interface{}) (*Job, error) {
	q.mu.RLock()
	_, exists := q.handlers[jobType]
	q.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no handler registered for job type: %s", jobType)
	}

	job := &Job{
		ID:         fmt.Sprintf("%s_%d", jobType, time.Now().UnixNano()),
		Type:       jobType,
		Status:     StatusPending,
		CreatedAt:  time.Now(),
		Data:       data,
		MaxRetries: q.maxRetries,
	}

	q.mu.Lock()
	q.jobs[job.ID] = job
	q.mu.Unlock()

	q.workChan <- job

	logger.Log.WithFields(map[string]interface{}{
		"action":   "job_enqueued",
		"job_id":   job.ID,
		"job_type": jobType,
	}).Info("Job enqueued")

	return job, nil
}

// GetJob retrieves a job by ID
func (q *Queue) GetJob(jobID string) (*Job, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	job, exists := q.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	return job, nil
}

// ListJobs returns all jobs
func (q *Queue) ListJobs(status JobStatus) []*Job {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var result []*Job
	for _, job := range q.jobs {
		if status == "" || job.Status == status {
			result = append(result, job)
		}
	}

	return result
}

// CancelJob cancels a pending or retrying job
func (q *Queue) CancelJob(jobID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	job, exists := q.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.Status != StatusPending && job.Status != StatusRetrying {
		return fmt.Errorf("cannot cancel job with status: %s", job.Status)
	}

	job.Status = StatusFailed
	job.Error = "Cancelled by user"

	logger.Log.WithFields(map[string]interface{}{
		"action": "job_cancelled",
		"job_id": jobID,
	}).Info("Job cancelled")

	return nil
}

// worker processes jobs from the queue
func (q *Queue) worker(id int) {
	for job := range q.workChan {
		q.processJob(id, job)
	}
}

// processJob executes a job with retry logic
func (q *Queue) processJob(workerID int, job *Job) {
	q.mu.Lock()
	job.Status = StatusRunning
	now := time.Now()
	job.StartedAt = &now
	q.mu.Unlock()

	logger.Log.WithFields(map[string]interface{}{
		"action":    "job_started",
		"worker_id": workerID,
		"job_id":    job.ID,
		"job_type":  job.Type,
	}).Info("Processing job")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Get handler
	q.mu.RLock()
	handler, exists := q.handlers[job.Type]
	q.mu.RUnlock()

	if !exists {
		q.mu.Lock()
		job.Status = StatusFailed
		job.Error = fmt.Sprintf("handler not found for job type: %s", job.Type)
		q.mu.Unlock()
		return
	}

	// Execute job with retries
	for attempt := 0; attempt <= job.MaxRetries; attempt++ {
		err := handler(ctx, job)

		if err == nil {
			// Success
			q.mu.Lock()
			job.Status = StatusCompleted
			now := time.Now()
			job.CompletedAt = &now
			q.mu.Unlock()

			logger.Log.WithFields(map[string]interface{}{
				"action":   "job_completed",
				"job_id":   job.ID,
				"job_type": job.Type,
			}).Info("Job completed successfully")

			return
		}

		// Failed
		logger.Log.WithFields(map[string]interface{}{
			"action":   "job_failed",
			"job_id":   job.ID,
			"attempt":  attempt + 1,
			"max":      job.MaxRetries + 1,
			"error":    err.Error(),
		}).Warn("Job execution failed")

		if attempt < job.MaxRetries {
			// Retry with exponential backoff
			backoff := time.Duration((attempt+1)*2) * time.Second
			q.mu.Lock()
			job.Status = StatusRetrying
			job.Retries = attempt + 1
			q.mu.Unlock()

			logger.Log.WithFields(map[string]interface{}{
				"action":   "job_retrying",
				"job_id":   job.ID,
				"backoff":  backoff.String(),
				"attempt":  attempt + 1,
			}).Info("Retrying job")

			time.Sleep(backoff)
		} else {
			// Max retries exceeded
			q.mu.Lock()
			job.Status = StatusFailed
			job.Error = err.Error()
			job.Retries = attempt
			now := time.Now()
			job.CompletedAt = &now
			q.mu.Unlock()

			logger.Log.WithFields(map[string]interface{}{
				"action":   "job_failed_final",
				"job_id":   job.ID,
				"error":    err.Error(),
			}).Error("Job failed after max retries")

			return
		}
	}
}

// GetStats returns queue statistics
func (q *Queue) GetStats() map[string]interface{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	stats := map[string]int{
		"total":      0,
		"pending":    0,
		"running":    0,
		"completed":  0,
		"failed":     0,
		"retrying":   0,
	}

	for _, job := range q.jobs {
		stats["total"]++
		switch job.Status {
		case StatusPending:
			stats["pending"]++
		case StatusRunning:
			stats["running"]++
		case StatusCompleted:
			stats["completed"]++
		case StatusFailed:
			stats["failed"]++
		case StatusRetrying:
			stats["retrying"]++
		}
	}

	return map[string]interface{}{
		"queue_stats": stats,
		"handlers":    len(q.handlers),
		"workers":     q.workers,
	}
}

// Shutdown gracefully shuts down the queue
func (q *Queue) Shutdown(timeout time.Duration) error {
	logger.Log.Info("Shutting down job queue")

	close(q.workChan)

	// Wait for pending jobs to complete
	deadline := time.Now().Add(timeout)
	for {
		q.mu.RLock()
		allDone := true
		for _, job := range q.jobs {
			if job.Status == StatusPending || job.Status == StatusRunning || job.Status == StatusRetrying {
				allDone = false
				break
			}
		}
		q.mu.RUnlock()

		if allDone {
			break
		}

		if time.Now().After(deadline) {
			logger.Log.Warn("Job queue shutdown timeout - some jobs still running")
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	logger.Log.Info("Job queue shutdown complete")
	return nil
}
