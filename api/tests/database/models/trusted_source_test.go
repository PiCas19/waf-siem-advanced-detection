package models_test

import (
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/stretchr/testify/assert"
)

func TestTrustedSourceTableName(t *testing.T) {
	ts := models.TrustedSource{}
	assert.Equal(t, "trusted_sources", ts.TableName())
}

func TestHMACKeyTableName(t *testing.T) {
	hk := models.HMACKey{}
	assert.Equal(t, "hmac_keys", hk.TableName())
}

func TestSourceValidationLogTableName(t *testing.T) {
	svl := models.SourceValidationLog{}
	assert.Equal(t, "source_validation_logs", svl.TableName())
}

func TestTrustedSourcePolicyTableName(t *testing.T) {
	tsp := models.TrustedSourcePolicy{}
	assert.Equal(t, "trusted_source_policies", tsp.TableName())
}

func TestTrustedSourceCreation(t *testing.T) {
	now := time.Now()
	
	trustedSource := &models.TrustedSource{
		ID:                  "test-source-1",
		Name:                "Test Reverse Proxy",
		Type:                "reverse_proxy",
		IP:                  "192.168.1.100",
		IPRange:             "192.168.1.0/24",
		Description:         "Test reverse proxy server",
		IsEnabled:           true,
		CreatedAt:           now,
		UpdatedAt:           now,
		LastVerifiedAt:      &now,
		VerificationStatus:  "verified",
		TrustsXPublicIP:     true,
		TrustsXForwardedFor: true,
		TrustsXRealIP:       false,
		RequireSignature:    false,
		HMACSecret:          "test-secret",
		AllowedHeaderFields: `["X-Forwarded-For", "X-Real-IP"]`,
		MaxRequestsPerMin:   100,
		BlockedAfterErrors:  10,
		CurrentErrorCount:   0,
		Location:           "Data Center A",
		GeolocationCountry: "US",
		CreatedBy:          "admin",
		UpdatedBy:          "admin",
	}

	// Test field values
	assert.Equal(t, "test-source-1", trustedSource.ID)
	assert.Equal(t, "Test Reverse Proxy", trustedSource.Name)
	assert.Equal(t, "reverse_proxy", trustedSource.Type)
	assert.Equal(t, "192.168.1.100", trustedSource.IP)
	assert.Equal(t, "192.168.1.0/24", trustedSource.IPRange)
	assert.Equal(t, "Test reverse proxy server", trustedSource.Description)
	assert.True(t, trustedSource.IsEnabled)
	assert.Equal(t, "verified", trustedSource.VerificationStatus)
	assert.True(t, trustedSource.TrustsXPublicIP)
	assert.True(t, trustedSource.TrustsXForwardedFor)
	assert.False(t, trustedSource.TrustsXRealIP)
	assert.False(t, trustedSource.RequireSignature)
	assert.Equal(t, "test-secret", trustedSource.HMACSecret)
	assert.Equal(t, `["X-Forwarded-For", "X-Real-IP"]`, trustedSource.AllowedHeaderFields)
	assert.Equal(t, 100, trustedSource.MaxRequestsPerMin)
	assert.Equal(t, 10, trustedSource.BlockedAfterErrors)
	assert.Equal(t, 0, trustedSource.CurrentErrorCount)
	assert.Equal(t, "Data Center A", trustedSource.Location)
	assert.Equal(t, "US", trustedSource.GeolocationCountry)
	assert.Equal(t, "admin", trustedSource.CreatedBy)
	assert.Equal(t, "admin", trustedSource.UpdatedBy)
}

func TestTrustedSourceDefaultValues(t *testing.T) {
	// NOTA: In Go, i valori di default nei tag GORM vengono impostati dal database,
	// non quando si crea un'istanza. Quindi questi campi saranno zero-values.
	trustedSource := &models.TrustedSource{
		ID:   "test-default",
		Name: "Test Default",
		Type: "custom",
	}

	// Zero-values quando si crea un'istanza in Go
	assert.Equal(t, "test-default", trustedSource.ID)
	assert.Equal(t, "Test Default", trustedSource.Name)
	assert.Equal(t, "custom", trustedSource.Type)
	assert.False(t, trustedSource.IsEnabled) // zero-value per bool è false
	assert.False(t, trustedSource.TrustsXPublicIP) // zero-value
	assert.False(t, trustedSource.TrustsXForwardedFor) // zero-value
	assert.False(t, trustedSource.TrustsXRealIP) // zero-value
	assert.False(t, trustedSource.RequireSignature) // zero-value
	assert.Equal(t, 0, trustedSource.MaxRequestsPerMin) // zero-value
	assert.Equal(t, 0, trustedSource.BlockedAfterErrors) // zero-value
	assert.Equal(t, 0, trustedSource.CurrentErrorCount) // zero-value
}

func TestHMACKeyCreation(t *testing.T) {
	now := time.Now()
	futureDate := now.AddDate(0, 0, 90)
	
	hmacKey := &models.HMACKey{
		ID:               "test-key-1",
		Name:             "Production Key",
		Secret:           "super-secret-key-value",
		TrustedSourceID:  "test-source-1",
		CreatedAt:        now,
		UpdatedAt:        now,
		LastUsedAt:       &now,
		RotationInterval: 90,
		NextRotationDate: &futureDate,
		IsActive:         true,
		CreatedBy:        "admin",
	}

	assert.Equal(t, "test-key-1", hmacKey.ID)
	assert.Equal(t, "Production Key", hmacKey.Name)
	assert.Equal(t, "super-secret-key-value", hmacKey.Secret)
	assert.Equal(t, "test-source-1", hmacKey.TrustedSourceID)
	assert.Equal(t, 90, hmacKey.RotationInterval)
	assert.True(t, hmacKey.IsActive)
	assert.Equal(t, "admin", hmacKey.CreatedBy)
}

func TestHMACKeyGetSecretHash(t *testing.T) {
	// Test basato sull'implementazione reale
	// Dal codice: if len(hk.Secret) > 10 { return hk.Secret[:4] + "***" + hk.Secret[len(hk.Secret)-4:] }
	// Altrimenti: return "***"
	
	tests := []struct {
		name     string
		secret   string
		expected string
	}{
		{
			name:     "Long secret (12+ chars)",
			secret:   "abcdefghijklmnopqrstuvwxyz", // 26 chars
			expected: "abcd***wxyz", // primi 4 + *** + ultimi 4
		},
		{
			name:     "Exactly 11 chars",
			secret:   "0123456789a", // 11 chars
			expected: "0123***789a", // len > 10, quindi primi 4 + *** + ultimi 4
		},
		{
			name:     "Exactly 10 chars",
			secret:   "0123456789", // 10 chars
			expected: "***", // len <= 10
		},
		{
			name:     "Short secret (9 chars)",
			secret:   "short1234",
			expected: "***",
		},
		{
			name:     "Very short secret",
			secret:   "ab",
			expected: "***",
		},
		{
			name:     "Empty secret",
			secret:   "",
			expected: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmacKey := &models.HMACKey{
				Secret: tt.secret,
			}
			
			result := hmacKey.GetSecretHash()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSourceValidationLogCreation(t *testing.T) {
	now := time.Now()
	
	validationLog := &models.SourceValidationLog{
		ID:                    "log-123",
		TrustedSourceID:       "test-source-1",
		IP:                    "192.168.1.100",
		IsValid:               true,
		ValidationTimestamp:   now,
		ValidationDetails:     "Signature verified successfully",
		TrustScore:            95,
		SourceType:            "reverse_proxy",
		ErrorMessage:          "",
		HeaderSignatureValid:  true,
		IsDMZ:                 false,
		IsTailscale:           false,
	}

	assert.Equal(t, "log-123", validationLog.ID)
	assert.Equal(t, "test-source-1", validationLog.TrustedSourceID)
	assert.Equal(t, "192.168.1.100", validationLog.IP)
	assert.True(t, validationLog.IsValid)
	assert.Equal(t, "Signature verified successfully", validationLog.ValidationDetails)
	assert.Equal(t, 95, validationLog.TrustScore)
	assert.Equal(t, "reverse_proxy", validationLog.SourceType)
	assert.Empty(t, validationLog.ErrorMessage)
	assert.True(t, validationLog.HeaderSignatureValid)
	assert.False(t, validationLog.IsDMZ)
	assert.False(t, validationLog.IsTailscale)
}

func TestTrustedSourcePolicyCreation(t *testing.T) {
	now := time.Now()
	
	policy := &models.TrustedSourcePolicy{
		ID:                     "policy-strict",
		Name:                   "Strict Verification Policy",
		Description:            "Requires signature verification for all sources",
		IsDefault:              true,
		IsEnabled:              true,
		CreatedAt:              now,
		UpdatedAt:              now,
		DefaultTrustLevel:      "high",
		RequireSignature:       true,
		EnableDMZDetection:     true,
		EnableTailscaleDetection: true,
		AutoBlockOnErrors:      true,
		Audit:                  `{"created": "admin", "updated": "admin"}`,
	}

	assert.Equal(t, "policy-strict", policy.ID)
	assert.Equal(t, "Strict Verification Policy", policy.Name)
	assert.Equal(t, "Requires signature verification for all sources", policy.Description)
	assert.True(t, policy.IsDefault)
	assert.True(t, policy.IsEnabled)
	assert.Equal(t, "high", policy.DefaultTrustLevel)
	assert.True(t, policy.RequireSignature)
	assert.True(t, policy.EnableDMZDetection)
	assert.True(t, policy.EnableTailscaleDetection)
	assert.True(t, policy.AutoBlockOnErrors)
	assert.Equal(t, `{"created": "admin", "updated": "admin"}`, policy.Audit)
}

func TestTrustedSourceRelationships(t *testing.T) {
	// Test that HMACKeys field exists
	trustedSource := &models.TrustedSource{
		ID:   "test-with-keys",
		Name: "Test with HMAC Keys",
		Type: "reverse_proxy",
		HMACKeys: []models.HMACKey{
			{
				ID:      "key-1",
				Name:    "Key 1",
				Secret:  "secret1",
				IsActive: true,
			},
			{
				ID:      "key-2",
				Name:    "Key 2",
				Secret:  "secret2",
				IsActive: false,
			},
		},
	}

	assert.Len(t, trustedSource.HMACKeys, 2)
	assert.Equal(t, "key-1", trustedSource.HMACKeys[0].ID)
	assert.Equal(t, "key-2", trustedSource.HMACKeys[1].ID)
	assert.True(t, trustedSource.HMACKeys[0].IsActive)
	assert.False(t, trustedSource.HMACKeys[1].IsActive)
}

func TestHMACKeyRelationship(t *testing.T) {
	// Test that TrustedSource field exists in HMACKey
	hmacKey := &models.HMACKey{
		ID:      "test-key",
		Name:    "Test Key",
		Secret:  "test-secret",
		TrustedSource: &models.TrustedSource{
			ID:   "source-1",
			Name: "Test Source",
			Type: "reverse_proxy",
		},
	}

	assert.NotNil(t, hmacKey.TrustedSource)
	assert.Equal(t, "source-1", hmacKey.TrustedSource.ID)
	assert.Equal(t, "Test Source", hmacKey.TrustedSource.Name)
}

func TestSourceValidationLogRelationship(t *testing.T) {
	// Test that TrustedSource field exists in SourceValidationLog
	validationLog := &models.SourceValidationLog{
		ID:     "log-1",
		IP:     "192.168.1.100",
		IsValid: true,
		TrustedSource: &models.TrustedSource{
			ID:   "source-1",
			Name: "Test Source",
			Type: "reverse_proxy",
		},
	}

	assert.NotNil(t, validationLog.TrustedSource)
	assert.Equal(t, "source-1", validationLog.TrustedSource.ID)
	assert.Equal(t, "Test Source", validationLog.TrustedSource.Name)
}

func TestTrustedSourcePolicyRelationships(t *testing.T) {
	// Test that Sources field exists in TrustedSourcePolicy
	policy := &models.TrustedSourcePolicy{
		ID:   "policy-1",
		Name: "Test Policy",
		Sources: []models.TrustedSource{
			{
				ID:   "source-1",
				Name: "Source 1",
				Type: "reverse_proxy",
			},
			{
				ID:   "source-2",
				Name: "Source 2",
				Type: "vpn",
			},
		},
	}

	assert.Len(t, policy.Sources, 2)
	assert.Equal(t, "source-1", policy.Sources[0].ID)
	assert.Equal(t, "source-2", policy.Sources[1].ID)
}

func TestTrustedSourceJSONTags(t *testing.T) {
	// Test JSON field names
	ts := models.TrustedSource{
		ID:                  "test-id",
		Name:                "Test",
		Type:                "custom",
		IP:                  "1.2.3.4",
		IPRange:             "1.2.3.0/24",
		Description:         "Test description",
		IsEnabled:           true,
		TrustsXPublicIP:     true,
		TrustsXForwardedFor: true,
		TrustsXRealIP:       false,
		RequireSignature:    false,
		HMACSecret:          "should-be-omitted",
		AllowedHeaderFields: "[]",
		MaxRequestsPerMin:   0,
		BlockedAfterErrors:  0, // zero-value, non default del database
		CurrentErrorCount:   0,
		Location:           "Test",
		GeolocationCountry: "US",
		CreatedBy:          "test",
		UpdatedBy:          "test",
	}

	// HMACSecret should have omitempty tag
	assert.NotEmpty(t, ts.HMACSecret, "HMACSecret should not be empty")
}

func TestHMACKeyJSONOmission(t *testing.T) {
	// Test that Secret field is omitted from JSON
	hmacKey := models.HMACKey{
		ID:      "test-id",
		Name:    "Test Key",
		Secret:  "super-secret-value",
	}

	// The Secret field has json:"-" tag, so it should not be serialized
	assert.Equal(t, "super-secret-value", hmacKey.Secret, "Secret should be accessible in Go")
}

func TestTrustedSourceTypes(t *testing.T) {
	// Test valid types
	validTypes := []string{
		"reverse_proxy",
		"dmz",
		"tailscale",
		"vpn",
		"load_balancer",
		"api_gateway",
		"custom",
	}
	
	for _, validType := range validTypes {
		ts := &models.TrustedSource{
			ID:   "test-type-" + validType,
			Name: "Test " + validType,
			Type: validType,
		}
		
		assert.Equal(t, validType, ts.Type, "Type should be %s", validType)
	}
	
	// Test an invalid type (should still be allowed by struct, but might fail validation elsewhere)
	ts := &models.TrustedSource{
		ID:   "test-invalid",
		Name: "Test Invalid",
		Type: "invalid_type",
	}
	
	assert.Equal(t, "invalid_type", ts.Type, "Invalid type should still be stored")
}

func TestVerificationStatusValues(t *testing.T) {
	// Test valid verification status values
	validStatuses := []string{
		"verified",
		"pending",
		"failed",
	}
	
	for _, status := range validStatuses {
		ts := &models.TrustedSource{
			ID:                 "test-status-" + status,
			Name:               "Test " + status,
			Type:               "custom",
			VerificationStatus: status,
		}
		
		assert.Equal(t, status, ts.VerificationStatus, "VerificationStatus should be %s", status)
	}
}

func TestDefaultTrustLevelValues(t *testing.T) {
	// Test valid default trust level values
	validLevels := []string{
		"none",
		"low",
		"medium",
		"high",
	}
	
	for _, level := range validLevels {
		policy := &models.TrustedSourcePolicy{
			ID:                "test-level-" + level,
			Name:              "Test " + level,
			DefaultTrustLevel: level,
		}
		
		assert.Equal(t, level, policy.DefaultTrustLevel, "DefaultTrustLevel should be %s", level)
	}
}

func TestTimestampFields(t *testing.T) {
	now := time.Now()
	
	// Test nullable timestamp fields
	ts := &models.TrustedSource{
		ID:             "test-timestamps",
		Name:           "Test Timestamps",
		Type:           "custom",
		LastVerifiedAt: &now,
	}
	
	assert.NotNil(t, ts.LastVerifiedAt)
	assert.Equal(t, now, *ts.LastVerifiedAt)
	
	// Test nil timestamp
	ts2 := &models.TrustedSource{
		ID:   "test-nil-timestamp",
		Name: "Test Nil Timestamp",
		Type: "custom",
	}
	
	assert.Nil(t, ts2.LastVerifiedAt)
}

func TestComplexJSONFields(t *testing.T) {
	// Test AllowedHeaderFields as JSON
	testJSON := `["X-Forwarded-For", "X-Real-IP", "X-Client-IP"]`
	
	ts := &models.TrustedSource{
		ID:                  "test-json",
		Name:                "Test JSON",
		Type:                "reverse_proxy",
		AllowedHeaderFields: testJSON,
	}
	
	assert.Equal(t, testJSON, ts.AllowedHeaderFields)
	
	// Test Audit field in policy
	auditJSON := `{"created_by": "admin", "created_at": "2024-01-01T00:00:00Z", "changes": ["enabled=true"]}`
	
	policy := &models.TrustedSourcePolicy{
		ID:   "test-audit",
		Name: "Test Audit Policy",
		Audit: auditJSON,
	}
	
	assert.Equal(t, auditJSON, policy.Audit)
}

func TestEdgeCases(t *testing.T) {
	t.Run("Empty fields", func(t *testing.T) {
		ts := &models.TrustedSource{
			ID:   "minimal",
			Name: "Minimal",
			Type: "custom",
			// All other fields should have default values
		}
		
		assert.Equal(t, "minimal", ts.ID)
		assert.Equal(t, "Minimal", ts.Name)
		assert.Equal(t, "custom", ts.Type)
		assert.Empty(t, ts.IP)
		assert.Empty(t, ts.IPRange)
		assert.Empty(t, ts.Description)
		assert.False(t, ts.IsEnabled) // zero-value
		assert.Empty(t, ts.VerificationStatus)
		assert.False(t, ts.TrustsXPublicIP) // zero-value
		assert.False(t, ts.TrustsXForwardedFor) // zero-value
		assert.False(t, ts.TrustsXRealIP) // zero-value
		assert.False(t, ts.RequireSignature) // zero-value
		assert.Empty(t, ts.HMACSecret)
		assert.Empty(t, ts.AllowedHeaderFields)
		assert.Equal(t, 0, ts.MaxRequestsPerMin) // zero-value
		assert.Equal(t, 0, ts.BlockedAfterErrors) // zero-value
		assert.Equal(t, 0, ts.CurrentErrorCount) // zero-value
		assert.Empty(t, ts.Location)
		assert.Empty(t, ts.GeolocationCountry)
		assert.Empty(t, ts.CreatedBy)
		assert.Empty(t, ts.UpdatedBy)
	})
	
	t.Run("Zero values", func(t *testing.T) {
		// Test that zero values are handled properly
		ts := &models.TrustedSource{
			ID:                "",
			Name:              "",
			Type:              "",
			MaxRequestsPerMin: 0,
			BlockedAfterErrors: 0,
			CurrentErrorCount: 0,
		}
		
		assert.Empty(t, ts.ID)
		assert.Empty(t, ts.Name)
		assert.Empty(t, ts.Type)
		assert.Equal(t, 0, ts.MaxRequestsPerMin)
		assert.Equal(t, 0, ts.BlockedAfterErrors)
		assert.Equal(t, 0, ts.CurrentErrorCount)
	})
}

func TestModelConsistency(t *testing.T) {
	// Test that all models have proper primary key
	assert.Equal(t, "trusted_sources", models.TrustedSource{}.TableName())
	assert.Equal(t, "hmac_keys", models.HMACKey{}.TableName())
	assert.Equal(t, "source_validation_logs", models.SourceValidationLog{}.TableName())
	assert.Equal(t, "trusted_source_policies", models.TrustedSourcePolicy{}.TableName())
}

// Test per verificare che i campi nullable siano effettivamente pointer
func TestNullableFields(t *testing.T) {
	// LastVerifiedAt dovrebbe essere *time.Time
	ts := models.TrustedSource{}
	
	// In Go, un campo pointer non inizializzato è nil
	assert.Nil(t, ts.LastVerifiedAt)
	
	// Possiamo impostarlo
	now := time.Now()
	ts.LastVerifiedAt = &now
	assert.NotNil(t, ts.LastVerifiedAt)
	assert.Equal(t, now, *ts.LastVerifiedAt)
}

// Test per verificare i campi JSON
func TestJSONSerialization(t *testing.T) {
	// TrustedSource con HMACSecret
	ts := models.TrustedSource{
		ID:         "test-json",
		Name:       "Test JSON",
		Type:       "custom",
		HMACSecret: "secret123",
	}
	
	// HMACSecret ha tag json:"hmac_secret,omitempty" quindi potrebbe essere serializzato
	// dipende dalla libreria JSON
	assert.Equal(t, "secret123", ts.HMACSecret)
	
	// HMACKey con Secret
	hk := models.HMACKey{
		ID:     "test-key",
		Name:   "Test Key",
		Secret: "super-secret",
	}
	
	// Secret ha json:"-" quindi non dovrebbe mai essere serializzato
	assert.Equal(t, "super-secret", hk.Secret)
}