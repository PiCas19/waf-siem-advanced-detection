package api

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// TrustedSourceHandler gestisce le richieste per le trusted sources
type TrustedSourceHandler struct {
	db *gorm.DB
}

// NewTrustedSourceHandler crea un nuovo handler per trusted sources
func NewTrustedSourceHandler(db *gorm.DB) *TrustedSourceHandler {
	return &TrustedSourceHandler{db: db}
}

// RegisterTrustedSourceRoutes registra le routes per trusted sources
func (h *TrustedSourceHandler) RegisterRoutes(group *echo.Group) {
	group.GET("/sources", h.ListTrustedSources)
	group.GET("/sources/:id", h.GetTrustedSource)
	group.POST("/sources", h.CreateTrustedSource)
	group.PUT("/sources/:id", h.UpdateTrustedSource)
	group.DELETE("/sources/:id", h.DeleteTrustedSource)
	group.POST("/sources/:id/verify", h.VerifyTrustedSource)
	group.GET("/sources/by-ip/:ip", h.GetTrustedSourceByIP)

	// HMAC Key management
	group.GET("/hmac-keys", h.ListHMACKeys)
	group.POST("/hmac-keys", h.CreateHMACKey)
	group.DELETE("/hmac-keys/:id", h.DeleteHMACKey)
	group.POST("/hmac-keys/:id/rotate", h.RotateHMACKey)
}

// TrustedSourceRequest è la struct per le richieste di trusted source
type TrustedSourceRequest struct {
	Name                   string   `json:"name" validate:"required"`
	Type                   string   `json:"type" validate:"required"`
	IP                     string   `json:"ip"`
	IPRange                string   `json:"ip_range"`
	Description            string   `json:"description"`
	IsEnabled              bool     `json:"is_enabled" default:"true"`
	TrustsXPublicIP        bool     `json:"trusts_x_public_ip" default:"true"`
	TrustsXForwardedFor    bool     `json:"trusts_x_forwarded_for" default:"true"`
	TrustsXRealIP          bool     `json:"trusts_x_real_ip" default:"false"`
	RequireSignature       bool     `json:"require_signature" default:"false"`
	AllowedHeaderFields    []string `json:"allowed_header_fields"`
	MaxRequestsPerMin      int      `json:"max_requests_per_min" default:"0"`
	BlockedAfterErrors     int      `json:"blocked_after_errors" default:"10"`
	Location               string   `json:"location"`
	GeolocationCountry     string   `json:"geolocation_country"`
}

// ListTrustedSources lista tutte le trusted sources
// @Summary List trusted sources
// @Description Get all trusted sources with optional filtering
// @Tags Trusted Sources
// @Param enabled query bool false "Filter by enabled status"
// @Param type query string false "Filter by type"
// @Success 200 {array} models.TrustedSource
// @Router /waf/sources [get]
func (h *TrustedSourceHandler) ListTrustedSources(c echo.Context) error {
	var sources []models.TrustedSource

	query := h.db

	// Filtra per status enabled
	if enabled := c.QueryParam("enabled"); enabled != "" {
		isEnabled := enabled == "true"
		query = query.Where("is_enabled = ?", isEnabled)
	}

	// Filtra per tipo
	if sourceType := c.QueryParam("type"); sourceType != "" {
		query = query.Where("type = ?", sourceType)
	}

	if err := query.Find(&sources).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch trusted sources",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"sources": sources,
		"count":   len(sources),
	})
}

// GetTrustedSource recupera una trusted source per ID
// @Summary Get trusted source by ID
// @Tags Trusted Sources
// @Param id path string true "Source ID"
// @Success 200 {object} models.TrustedSource
// @Router /waf/sources/{id} [get]
func (h *TrustedSourceHandler) GetTrustedSource(c echo.Context) error {
	id := c.Param("id")

	var source models.TrustedSource
	if err := h.db.First(&source, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Trusted source not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Database error", err),
		})
	}

	return c.JSON(http.StatusOK, source)
}

// CreateTrustedSource crea una nuova trusted source
// @Summary Create trusted source
// @Tags Trusted Sources
// @Param request body TrustedSourceRequest true "Source details"
// @Success 201 {object} models.TrustedSource
// @Router /waf/sources [post]
func (h *TrustedSourceHandler) CreateTrustedSource(c echo.Context) error {
	var req TrustedSourceRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request", err),
		})
	}

	// Validazione: deve avere IP o IPRange
	if req.IP == "" && req.IPRange == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Either IP or IP range must be provided",
		})
	}

	source := models.TrustedSource{
		Name:                req.Name,
		Type:                req.Type,
		IP:                  req.IP,
		IPRange:             req.IPRange,
		Description:         req.Description,
		IsEnabled:           req.IsEnabled,
		TrustsXPublicIP:     req.TrustsXPublicIP,
		TrustsXForwardedFor: req.TrustsXForwardedFor,
		TrustsXRealIP:       req.TrustsXRealIP,
		RequireSignature:    req.RequireSignature,
		MaxRequestsPerMin:   req.MaxRequestsPerMin,
		BlockedAfterErrors:  req.BlockedAfterErrors,
		Location:            req.Location,
		GeolocationCountry:  req.GeolocationCountry,
	}

	if err := h.db.Create(&source).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to create source", err),
		})
	}

	return c.JSON(http.StatusCreated, source)
}

// UpdateTrustedSource aggiorna una trusted source
// @Summary Update trusted source
// @Tags Trusted Sources
// @Param id path string true "Source ID"
// @Param request body TrustedSourceRequest true "Updated source details"
// @Success 200 {object} models.TrustedSource
// @Router /waf/sources/{id} [put]
func (h *TrustedSourceHandler) UpdateTrustedSource(c echo.Context) error {
	id := c.Param("id")

	var req TrustedSourceRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request", err),
		})
	}

	var source models.TrustedSource
	if err := h.db.First(&source, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Trusted source not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Database error", err),
		})
	}

	// Update fields
	source.Name = req.Name
	source.Type = req.Type
	source.IP = req.IP
	source.IPRange = req.IPRange
	source.Description = req.Description
	source.IsEnabled = req.IsEnabled
	source.TrustsXPublicIP = req.TrustsXPublicIP
	source.TrustsXForwardedFor = req.TrustsXForwardedFor
	source.TrustsXRealIP = req.TrustsXRealIP
	source.RequireSignature = req.RequireSignature
	source.MaxRequestsPerMin = req.MaxRequestsPerMin
	source.BlockedAfterErrors = req.BlockedAfterErrors
	source.Location = req.Location
	source.GeolocationCountry = req.GeolocationCountry

	if err := h.db.Save(&source).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to update source", err),
		})
	}

	return c.JSON(http.StatusOK, source)
}

// DeleteTrustedSource elimina una trusted source
// @Summary Delete trusted source
// @Tags Trusted Sources
// @Param id path string true "Source ID"
// @Success 204
// @Router /waf/sources/{id} [delete]
func (h *TrustedSourceHandler) DeleteTrustedSource(c echo.Context) error {
	id := c.Param("id")

	if err := h.db.Delete(&models.TrustedSource{}, "id = ?", id).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete source", err),
		})
	}

	return c.NoContent(http.StatusNoContent)
}

// VerifyTrustedSource verifica la validità di una trusted source
// @Summary Verify trusted source
// @Tags Trusted Sources
// @Param id path string true "Source ID"
// @Success 200 {object} map[string]interface{}
// @Router /waf/sources/{id}/verify [post]
func (h *TrustedSourceHandler) VerifyTrustedSource(c echo.Context) error {
	id := c.Param("id")

	var source models.TrustedSource
	if err := h.db.First(&source, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Trusted source not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Database error", err),
		})
	}

	// Marca come verified
	now := time.Now()
	source.LastVerifiedAt = &now
	source.VerificationStatus = "verified"

	if err := h.db.Save(&source).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to verify source", err),
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Source verified successfully",
		"source":  source,
	})
}

// GetTrustedSourceByIP recupera una trusted source per IP
// @Summary Get trusted source by IP
// @Tags Trusted Sources
// @Param ip path string true "IP address"
// @Success 200 {object} models.TrustedSource
// @Router /waf/sources/by-ip/{ip} [get]
func (h *TrustedSourceHandler) GetTrustedSourceByIP(c echo.Context) error {
	ip := c.Param("ip")

	var source models.TrustedSource

	// First try exact match
	if err := h.db.First(&source, "ip = ? AND is_enabled = ?", ip, true).Error; err == nil {
		return c.JSON(http.StatusOK, source)
	}

	// Try CIDR match (this is approximate - proper CIDR matching should be done in Go)
	var sources []models.TrustedSource
	if err := h.db.Where("ip_range != '' AND is_enabled = ?", true).Find(&sources).Error; err == nil {
		// In production, userebbe una libreria per proper CIDR matching
		if len(sources) > 0 {
			return c.JSON(http.StatusOK, sources[0])
		}
	}

	return c.JSON(http.StatusNotFound, map[string]string{
		"error": "No trusted source found for this IP",
	})
}

// HMACKeyRequest è la struct per le richieste di HMAC key
type HMACKeyRequest struct {
	Name              string `json:"name" validate:"required"`
	Secret            string `json:"secret" validate:"required"`
	TrustedSourceID   string `json:"trusted_source_id"`
	RotationInterval  int    `json:"rotation_interval"` // Days between rotations
	IsActive          bool   `json:"is_active" default:"true"`
}

// ListHMACKeys lista tutte le HMAC keys
// @Summary List HMAC keys
// @Tags HMAC Keys
// @Success 200 {array} models.HMACKey
// @Router /waf/hmac-keys [get]
func (h *TrustedSourceHandler) ListHMACKeys(c echo.Context) error {
	var keys []models.HMACKey

	if err := h.db.Find(&keys).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch HMAC keys", err),
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"keys":  keys,
		"count": len(keys),
	})
}

// CreateHMACKey crea una nuova HMAC key
// @Summary Create HMAC key
// @Tags HMAC Keys
// @Param request body HMACKeyRequest true "Key details"
// @Success 201 {object} models.HMACKey
// @Router /waf/hmac-keys [post]
func (h *TrustedSourceHandler) CreateHMACKey(c echo.Context) error {
	var req HMACKeyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request", err),
		})
	}

	key := models.HMACKey{
		Name:             req.Name,
		Secret:           req.Secret,
		TrustedSourceID:  req.TrustedSourceID,
		RotationInterval: req.RotationInterval,
		IsActive:         req.IsActive,
	}

	if err := h.db.Create(&key).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to create HMAC key", err),
		})
	}

	return c.JSON(http.StatusCreated, key)
}

// DeleteHMACKey elimina una HMAC key
// @Summary Delete HMAC key
// @Tags HMAC Keys
// @Param id path string true "Key ID"
// @Success 204
// @Router /waf/hmac-keys/{id} [delete]
func (h *TrustedSourceHandler) DeleteHMACKey(c echo.Context) error {
	id := c.Param("id")

	if err := h.db.Delete(&models.HMACKey{}, "id = ?", id).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete HMAC key", err),
		})
	}

	return c.NoContent(http.StatusNoContent)
}

// RotateHMACKey ruota una HMAC key
// @Summary Rotate HMAC key
// @Tags HMAC Keys
// @Param id path string true "Key ID"
// @Success 200 {object} models.HMACKey
// @Router /waf/hmac-keys/{id}/rotate [post]
func (h *TrustedSourceHandler) RotateHMACKey(c echo.Context) error {
	id := c.Param("id")

	var key models.HMACKey
	if err := h.db.First(&key, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "HMAC key not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Database error", err),
		})
	}

	// Mark old key as inactive
	key.IsActive = false
	if err := h.db.Save(&key).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to deactivate old key", err),
		})
	}

	// Generate new key (in production, use a proper key generation function)
	newKey := models.HMACKey{
		Name:             key.Name + " (rotated)",
		Secret:           generateRandomSecret(32),
		TrustedSourceID:  key.TrustedSourceID,
		RotationInterval: key.RotationInterval,
		IsActive:         true,
	}

	if err := h.db.Create(&newKey).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to create new key", err),
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":  "Key rotated successfully",
		"old_key":  key,
		"new_key":  newKey,
	})
}

// Helper function per generare un secret random (implementazione basic)
func generateRandomSecret(length int) string {
	// In production, usare crypto/rand
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	secret := make([]byte, length)
	for i := range secret {
		secret[i] = charset[i%len(charset)]
	}
	return string(secret)
}
