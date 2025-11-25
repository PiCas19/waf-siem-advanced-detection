package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HealthCheckResponse contains health status of the application
type HealthCheckResponse struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Uptime    string                 `json:"uptime"`
	Services  map[string]ServiceStatus `json:"services"`
}

// ServiceStatus contains status of individual service
type ServiceStatus struct {
	Status  string `json:"status"` // "healthy", "degraded", "unhealthy"
	Message string `json:"message,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

var startTime = time.Now()

// NewHealthCheckHandler godoc
// @Summary Comprehensive health check
// @Description Returns detailed health status of all critical services
// @Tags Health
// @Accept json
// @Produce json
// @Success 200 {object} HealthCheckResponse "All services healthy"
// @Failure 503 {object} HealthCheckResponse "One or more services unhealthy"
// @Router /health [get]
func NewHealthCheckHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		response := HealthCheckResponse{
			Timestamp: time.Now(),
			Uptime:    time.Since(startTime).String(),
			Services:  make(map[string]ServiceStatus),
		}

		// Check database
		response.Services["database"] = checkDatabase(db)

		// Check if all services are healthy
		allHealthy := true
		for _, service := range response.Services {
			if service.Status != "healthy" {
				allHealthy = false
				break
			}
		}

		if allHealthy {
			response.Status = "healthy"
			c.JSON(http.StatusOK, response)
		} else {
			response.Status = "degraded"
			c.JSON(http.StatusServiceUnavailable, response)
		}
	}
}

// checkDatabase checks if database is accessible
func checkDatabase(db *gorm.DB) ServiceStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sqlDB, err := db.WithContext(ctx).DB()
	if err != nil {
		return ServiceStatus{
			Status:  "unhealthy",
			Message: "Failed to get database connection",
			Details: map[string]interface{}{"error": err.Error()},
		}
	}

	// Test database connection
	if err := sqlDB.PingContext(ctx); err != nil {
		return ServiceStatus{
			Status:  "unhealthy",
			Message: "Database ping failed",
			Details: map[string]interface{}{"error": err.Error()},
		}
	}

	return ServiceStatus{
		Status:  "healthy",
		Message: "Database connection OK",
	}
}

// LivenessProbeHandler godoc
// @Summary Kubernetes liveness probe
// @Description Simple probe to check if service is running (Kubernetes compatible)
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string "Service is alive"
// @Router /health/live [get]
func LivenessProbeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	}
}

// ReadinessProbeHandler godoc
// @Summary Kubernetes readiness probe
// @Description Checks if service is ready to handle requests (Kubernetes compatible)
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string "Service is ready"
// @Failure 503 {object} map[string]string "Service not ready"
// @Router /health/ready [get]
func ReadinessProbeHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Quick database check
		dbStatus := checkDatabase(db)

		if dbStatus.Status == "healthy" {
			c.JSON(http.StatusOK, gin.H{"status": "ready"})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not_ready",
				"reason": dbStatus.Message,
			})
		}
	}
}
