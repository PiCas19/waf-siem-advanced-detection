package models

import (
	"time"

	"gorm.io/gorm"
)

// TrustedSource rappresenta una sorgente trusted (proxy, DMZ, Tailscale, ecc.)
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

// TableName specifica il nome della tabella
func (TrustedSource) TableName() string {
	return "trusted_sources"
}

// HMACKey rappresenta una chiave HMAC per la firma dei header
type HMACKey struct {
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

// TableName specifica il nome della tabella
func (HMACKey) TableName() string {
	return "hmac_keys"
}

// SourceValidationLog registra ogni validazione di una sorgente
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

// TableName specifica il nome della tabella
func (SourceValidationLog) TableName() string {
	return "source_validation_logs"
}

// TrustedSourcePolicy rappresenta una policy di trust
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
