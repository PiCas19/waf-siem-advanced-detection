package models

import (
	"time"

	"gorm.io/gorm"
)

// TrustedSource represents a trusted network source (reverse proxy, DMZ, Tailscale, VPN, etc.)
// that can provide reliable client IP information through HTTP headers.
//
// Fields:
//   - ID (string): Primary key identifier for the trusted source
//   - Name (string): Human-readable name of the trusted source
//   - Type (string): Type of source - reverse_proxy, dmz, tailscale, vpn, load_balancer, api_gateway, custom
//   - IP (string): Single IP address of the trusted source
//   - IPRange (string): CIDR range for the trusted source
//   - Description (string): Detailed description of this trusted source
//   - IsEnabled (bool): Whether this source is currently enabled (default: true)
//   - CreatedAt (time.Time): Timestamp when created
//   - UpdatedAt (time.Time): Timestamp of last update
//   - LastVerifiedAt (*time.Time): Timestamp of last verification check
//   - VerificationStatus (string): Verification status - verified, pending, failed
//   - TrustsXPublicIP (bool): Whether to trust X-Public-IP header (default: true)
//   - TrustsXForwardedFor (bool): Whether to trust X-Forwarded-For header (default: true)
//   - TrustsXRealIP (bool): Whether to trust X-Real-IP header (default: false)
//   - RequireSignature (bool): Whether HMAC signature is required (default: false)
//   - HMACSecret (string): HMAC secret for signature verification (not exported in JSON)
//   - AllowedHeaderFields (string): JSON array of allowed header fields
//   - MaxRequestsPerMin (int): Rate limit in requests per minute (0 = unlimited)
//   - BlockedAfterErrors (int): Number of errors before blocking (default: 10)
//   - CurrentErrorCount (int): Current error count (default: 0, resets hourly)
//   - Location (string): Physical/logical location of the source
//   - GeolocationCountry (string): Country code of the source
//   - CreatedBy (string): User who created this source
//   - UpdatedBy (string): User who last updated this source
//   - HMACKeys ([]HMACKey): Associated HMAC keys for signature verification
//
// Example Usage:
//   trustedSource := &models.TrustedSource{
//       ID: "nginx-proxy-1",
//       Name: "Main Nginx Proxy",
//       Type: "reverse_proxy",
//       IP: "10.0.1.5",
//       TrustsXForwardedFor: true,
//       IsEnabled: true,
//   }
//   db.Create(&trustedSource)
//
// Thread Safety: Not thread-safe. The BeforeUpdate hook modifies CurrentErrorCount
// which requires proper database locking in concurrent environments.
//
// See Also: HMACKey, SourceValidationLog, TrustedSourcePolicy
type TrustedSource struct {
	ID                  string    `gorm:"primaryKey" json:"id"`
	Name                string    `json:"name"`
	Type                string    `json:"type"` // reverse_proxy, dmz, tailscale, vpn, load_balancer, api_gateway, custom
	IP                  string    `json:"ip"`
	IPRange             string    `json:"ip_range"`      // CIDR range
	Description         string    `json:"description"`
	IsEnabled           bool      `json:"is_enabled" gorm:"default:true"`
	CreatedAt           time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt           time.Time `json:"updated_at" gorm:"autoUpdateTime"`
	LastVerifiedAt      *time.Time `json:"last_verified_at"`
	VerificationStatus  string    `json:"verification_status"` // verified, pending, failed

	// Configurazione header extraction
	TrustsXPublicIP    bool   `json:"trusts_x_public_ip" gorm:"default:true"`
	TrustsXForwardedFor bool  `json:"trusts_x_forwarded_for" gorm:"default:true"`
	TrustsXRealIP       bool  `json:"trusts_x_real_ip" gorm:"default:false"`
	RequireSignature    bool  `json:"require_signature" gorm:"default:false"`
	HMACSecret          string `json:"hmac_secret,omitempty"` // Non esportare in JSON nella risposta

	// Metadati di sicurezza
	AllowedHeaderFields string `json:"allowed_header_fields" gorm:"type:json"`
	MaxRequestsPerMin   int      `json:"max_requests_per_min" gorm:"default:0"`
	BlockedAfterErrors  int      `json:"blocked_after_errors" gorm:"default:10"`
	CurrentErrorCount   int      `json:"current_error_count" gorm:"default:0"`

	// Geolocation hints
	Location           string `json:"location"`
	GeolocationCountry string `json:"geolocation_country"`

	// Audit
	CreatedBy string `json:"created_by"`
	UpdatedBy string `json:"updated_by"`

	// Relationships
	HMACKeys []HMACKey `json:"hmac_keys,omitempty" gorm:"foreignKey:TrustedSourceID"`
}

// TableName specifies the database table name for TrustedSource
func (TrustedSource) TableName() string {
	return "trusted_sources"
}

// HMACKey represents an HMAC key used for signing and verifying HTTP headers from trusted sources.
//
// Fields:
//   - ID (string): Primary key identifier for the HMAC key
//   - Name (string): Human-readable name for this key
//   - Secret (string): The HMAC secret key (never exported in JSON)
//   - TrustedSourceID (string): Foreign key to the associated TrustedSource
//   - CreatedAt (time.Time): Timestamp when created
//   - UpdatedAt (time.Time): Timestamp of last update
//   - LastUsedAt (*time.Time): Timestamp of last successful use
//   - RotationInterval (int): Days between automatic key rotations
//   - NextRotationDate (*time.Time): When this key should be rotated
//   - IsActive (bool): Whether this key is currently active (default: true)
//   - CreatedBy (string): User who created this key
//   - TrustedSource (*TrustedSource): Associated TrustedSource object
//
// Example Usage:
//   hmacKey := &models.HMACKey{
//       ID: "key-1",
//       Name: "Production Key",
//       Secret: "secret-value-here",
//       TrustedSourceID: "nginx-proxy-1",
//       RotationInterval: 90,
//       IsActive: true,
//   }
//   db.Create(&hmacKey)
//
// Thread Safety: Not thread-safe. Use appropriate database locking when updating
// LastUsedAt or rotation fields concurrently.
//
// See Also: TrustedSource, GetSecretHash()
type HMACKey struct{
	ID               string    `gorm:"primaryKey" json:"id"`
	Name             string    `json:"name"`
	Secret           string    `json:"-"` // Non esportare mai il secret in JSON
	TrustedSourceID  string    `json:"trusted_source_id"`
	CreatedAt        time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt        time.Time `json:"updated_at" gorm:"autoUpdateTime"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	RotationInterval int       `json:"rotation_interval"` // Days between rotations
	NextRotationDate *time.Time `json:"next_rotation_date"`
	IsActive         bool      `json:"is_active" gorm:"default:true"`
	CreatedBy        string    `json:"created_by"`

	// Relationship
	TrustedSource *TrustedSource `json:"trusted_source,omitempty" gorm:"foreignKey:TrustedSourceID"`
}

// TableName specifies the database table name for HMACKey
func (HMACKey) TableName() string {
	return "hmac_keys"
}

// SourceValidationLog records each validation attempt for a trusted source.
//
// Fields:
//   - ID (string): Primary key identifier for the validation log entry
//   - TrustedSourceID (string): Foreign key to the associated TrustedSource
//   - IP (string): IP address being validated
//   - IsValid (bool): Whether the validation succeeded
//   - ValidationTimestamp (time.Time): When the validation occurred
//   - ValidationDetails (string): Additional details about the validation
//   - TrustScore (int): Calculated trust score (0-100)
//   - SourceType (string): Type of source that was validated
//   - ErrorMessage (string): Error message if validation failed
//   - HeaderSignatureValid (bool): Whether the HMAC signature was valid
//   - IsDMZ (bool): Whether the source is in a DMZ
//   - IsTailscale (bool): Whether the source is a Tailscale endpoint
//   - TrustedSource (*TrustedSource): Associated TrustedSource object
//
// Example Usage:
//   validationLog := &models.SourceValidationLog{
//       ID: "log-123",
//       TrustedSourceID: "nginx-proxy-1",
//       IP: "10.0.1.5",
//       IsValid: true,
//       TrustScore: 95,
//       HeaderSignatureValid: true,
//   }
//   db.Create(&validationLog)
//
// Thread Safety: Not thread-safe. Use appropriate database transaction handling
// when creating validation logs concurrently.
//
// See Also: TrustedSource
type SourceValidationLog struct {
	ID                 string    `gorm:"primaryKey" json:"id"`
	TrustedSourceID    string    `json:"trusted_source_id"`
	IP                 string    `json:"ip"`
	IsValid            bool      `json:"is_valid"`
	ValidationTimestamp time.Time `json:"validation_timestamp" gorm:"autoCreateTime"`
	ValidationDetails  string    `json:"validation_details"`
	TrustScore         int       `json:"trust_score"`
	SourceType         string    `json:"source_type"`
	ErrorMessage       string    `json:"error_message"`
	HeaderSignatureValid bool    `json:"header_signature_valid"`
	IsDMZ              bool    `json:"is_dmz"`
	IsTailscale        bool    `json:"is_tailscale"`

	// Relationship
	TrustedSource *TrustedSource `json:"trusted_source,omitempty" gorm:"foreignKey:TrustedSourceID"`
}

// TableName specifies the database table name for SourceValidationLog
func (SourceValidationLog) TableName() string {
	return "source_validation_logs"
}

// TrustedSourcePolicy represents a trust policy that can be applied to multiple trusted sources.
//
// Fields:
//   - ID (string): Primary key identifier for the policy
//   - Name (string): Human-readable name of the policy
//   - Description (string): Detailed description of what this policy does
//   - IsDefault (bool): Whether this is the default policy for new sources
//   - IsEnabled (bool): Whether this policy is currently enabled (default: true)
//   - CreatedAt (time.Time): Timestamp when created
//   - UpdatedAt (time.Time): Timestamp of last update
//   - DefaultTrustLevel (string): Default trust level - none, low, medium, high
//   - RequireSignature (bool): Whether HMAC signature is required for all sources
//   - EnableDMZDetection (bool): Whether DMZ detection is enabled
//   - EnableTailscaleDetection (bool): Whether Tailscale detection is enabled
//   - AutoBlockOnErrors (bool): Whether to automatically block sources after errors
//   - Sources ([]TrustedSource): Associated trusted sources (many-to-many relationship)
//   - Audit (string): JSON-encoded audit trail of policy changes
//
// Example Usage:
//   policy := &models.TrustedSourcePolicy{
//       ID: "policy-strict",
//       Name: "Strict Verification Policy",
//       Description: "Requires signature verification for all sources",
//       DefaultTrustLevel: "high",
//       RequireSignature: true,
//       IsEnabled: true,
//   }
//   db.Create(&policy)
//
// Thread Safety: Not thread-safe. Use appropriate database transaction handling
// when creating/modifying policies concurrently.
//
// See Also: TrustedSource
type TrustedSourcePolicy struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsDefault   bool      `json:"is_default"`
	IsEnabled   bool      `json:"is_enabled" gorm:"default:true"`
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"autoUpdateTime"`

	// Configurazione della policy
	DefaultTrustLevel    string `json:"default_trust_level"` // none, low, medium, high
	RequireSignature     bool   `json:"require_signature"`
	EnableDMZDetection   bool   `json:"enable_dmz_detection"`
	EnableTailscaleDetection bool `json:"enable_tailscale_detection"`
	AutoBlockOnErrors    bool   `json:"auto_block_on_errors"`

	// Relationships
	Sources []TrustedSource `json:"sources,omitempty" gorm:"many2many:policy_sources"`
	Audit   string          `json:"audit"` // JSON audit trail
}

// TableName specifica il nome della tabella
func (TrustedSourcePolicy) TableName() string {
	return "trusted_source_policies"
}

// BeforeUpdate hook per verificare il timestamp di LastVerifiedAt
func (ts *TrustedSource) BeforeUpdate(tx *gorm.DB) error {
	// Reset error count every hour if enabled
	if ts.UpdatedAt.Add(time.Hour).Before(time.Now()) {
		tx.Model(ts).Update("current_error_count", 0)
	}
	return nil
}

// GetSecretHash ritorna un hash del secret per logging/audit
func (hk *HMACKey) GetSecretHash() string {
	// In production, implementare un proper hashing
	if len(hk.Secret) > 10 {
		return hk.Secret[:4] + "***" + hk.Secret[len(hk.Secret)-4:]
	}
	return "***"
}
