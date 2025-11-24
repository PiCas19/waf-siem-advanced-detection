package worker

import (
	"context"
	"fmt"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/mailer"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/threatintel"
	"gorm.io/gorm"
)

// EnrichmentExecutor executes threat intelligence enrichment jobs
type EnrichmentExecutor struct {
	db              *gorm.DB
	enrichmentSvc   *threatintel.EnrichmentService
}

func NewEnrichmentExecutor(db *gorm.DB, enrichmentSvc *threatintel.EnrichmentService) JobExecutor {
	return &EnrichmentExecutor{
		db:            db,
		enrichmentSvc: enrichmentSvc,
	}
}

func (e *EnrichmentExecutor) Execute(ctx context.Context, job Job) error {
	enrichmentJob, ok := job.(*EnrichmentJob)
	if !ok {
		return fmt.Errorf("invalid job type")
	}

	// Fetch log from database
	var log interface{}
	// This will be implemented based on your actual Log model
	// For now, placeholder implementation
	_ = log

	// Perform enrichment
	// this is placeholder - will be implemented with actual enrichment logic
	logger.Log.WithField("ip", enrichmentJob.ip).Info("EnrichmentExecutor enriching IP")

	if enrichmentJob.onResult != nil {
		enrichmentJob.onResult(nil, nil)
	}

	return nil
}

// EmailExecutor executes email sending jobs
type EmailExecutor struct {
	mailer *mailer.Mailer
}

func NewEmailExecutor(mailer *mailer.Mailer) JobExecutor {
	return &EmailExecutor{
		mailer: mailer,
	}
}

func (e *EmailExecutor) Execute(ctx context.Context, job Job) error {
	emailJob, ok := job.(*EmailJob)
	if !ok {
		return fmt.Errorf("invalid job type")
	}

	// Send email
	if e.mailer == nil {
		return fmt.Errorf("mailer not configured")
	}

	err := e.mailer.SendEmail(emailJob.toEmail, emailJob.subject, emailJob.htmlBody)
	if emailJob.onResult != nil {
		emailJob.onResult(err)
	}

	if err != nil {
		return fmt.Errorf("failed to send email to %s: %w", emailJob.toEmail, err)
	}

	logger.Log.WithFields(map[string]interface{}{
		"to":      emailJob.toEmail,
		"subject": emailJob.subject,
	}).Info("EmailExecutor email sent")
	return nil
}

// CompositeExecutor handles multiple job types
type CompositeExecutor struct {
	executors map[string]JobExecutor
}

func NewCompositeExecutor() *CompositeExecutor {
	return &CompositeExecutor{
		executors: make(map[string]JobExecutor),
	}
}

func (c *CompositeExecutor) Register(jobType string, executor JobExecutor) {
	c.executors[jobType] = executor
}

func (c *CompositeExecutor) Execute(ctx context.Context, job Job) error {
	// Determine job type and route to appropriate executor
	switch job.(type) {
	case *EnrichmentJob:
		if executor, ok := c.executors["enrichment"]; ok {
			return executor.Execute(ctx, job)
		}
	case *EmailJob:
		if executor, ok := c.executors["email"]; ok {
			return executor.Execute(ctx, job)
		}
	}
	return fmt.Errorf("no executor registered for job type")
}
