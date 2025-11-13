package ipextract

import (
	"net"
	"sync"
	"time"
)

// TrustedSourceType definisce il tipo di sorgente trusted
type TrustedSourceType string

const (
	SourceTypeReverseProxy TrustedSourceType = "reverse_proxy"   // Nginx, Apache, Caddy, ecc.
	SourceTypeDMZ          TrustedSourceType = "dmz"             // DMZ network/appliance
	SourceTypeTailscale    TrustedSourceType = "tailscale"       // Tailscale node/network
	SourceTypeVPN          TrustedSourceType = "vpn"             // Generic VPN gateway
	SourceTypeLoadBalancer TrustedSourceType = "load_balancer"   // ELB, ALB, LB, ecc.
	SourceTypeAPIGateway   TrustedSourceType = "api_gateway"     // API Gateway, Kong, ecc.
	SourceTypeCustom       TrustedSourceType = "custom"          // Custom trusted source
)

// TrustedSource rappresenta una sorgente trusted (proxy, DMZ, Tailscale, ecc.)
type TrustedSource struct {
	ID                  string            // Unique identifier (es: "production-nginx-01")
	Name                string            // Human-readable name (es: "Production Nginx Reverse Proxy")
	Type                TrustedSourceType // Tipo di sorgente
	IP                  string            // IP address (singolo)
	IPRange             string            // CIDR range (es: "10.0.0.0/24")
	Description         string            // Descrizione della sorgente
	IsEnabled           bool              // Se disabled, non viene considerata trusted
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastVerifiedAt      *time.Time
	VerificationStatus  string            // "verified", "pending", "failed"

	// Configurazione header extraction
	TrustsXPublicIP    bool   // Se true, accetta X-Public-IP da questa sorgente
	TrustsXForwardedFor bool  // Se true, accetta X-Forwarded-For da questa sorgente
	TrustsXRealIP       bool  // Se true, accetta X-Real-IP da questa sorgente
	RequireSignature    bool  // Se true, richiede firma HMAC per tutti gli header
	HMACSecret          string // Secret HMAC per questa sorgente (opzionale, per firma)

	// Metadati di sicurezza
	AllowedHeaderFields []string // Headers aggiuntivi permessi da questa sorgente
	MaxRequestsPerMin   int      // Rate limiting per questa sorgente
	BlockedAfterErrors  int      // Auto-block dopo N errori di validazione
	CurrentErrorCount   int      // Counter errori (reset ogni ora)

	// Geolocation hints (opzionale)
	Location           string // Localizzazione della sorgente (es: "AWS us-east-1")
	GeolocationCountry string // Paese della sorgente

	// Audit
	CreatedBy string // User che ha creato questa sorgente
	UpdatedBy string // User che ha aggiornato questa sorgente
}

// TrustedSourcePolicy rappresenta una policy di trust per gestire più sorgenti
type TrustedSourcePolicy struct {
	ID          string
	Name        string
	Description string
	IsDefault   bool
	IsEnabled   bool

	Sources      map[string]*TrustedSource // Key: source IP or CIDR
	sourcesLock  sync.RWMutex

	// Configurazione globale della policy
	DefaultTrustLevel    string // "none", "low", "medium", "high"
	RequireSignature     bool   // Richiedi firma per tutti gli header custom
	EnableDMZDetection   bool
	EnableTailscaleDetection bool
	AutoBlockOnErrors    bool   // Auto-block sorgenti dopo troppe validazioni fallite

	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewTrustedSourcePolicy crea una nuova policy
func NewTrustedSourcePolicy(id, name string) *TrustedSourcePolicy {
	return &TrustedSourcePolicy{
		ID:                   id,
		Name:                 name,
		IsEnabled:            true,
		Sources:              make(map[string]*TrustedSource),
		DefaultTrustLevel:    "low",
		RequireSignature:     false,
		EnableDMZDetection:   false,
		EnableTailscaleDetection: false,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
}

// AddSource aggiunge una sorgente trusted alla policy
func (p *TrustedSourcePolicy) AddSource(source *TrustedSource) error {
	p.sourcesLock.Lock()
	defer p.sourcesLock.Unlock()

	key := source.IP
	if source.IP == "" && source.IPRange != "" {
		key = source.IPRange
	}

	source.CreatedAt = time.Now()
	source.UpdatedAt = time.Now()
	p.Sources[key] = source

	return nil
}

// RemoveSource rimuove una sorgente trusted dalla policy
func (p *TrustedSourcePolicy) RemoveSource(id string) {
	p.sourcesLock.Lock()
	defer p.sourcesLock.Unlock()

	delete(p.Sources, id)
}

// GetSourceByIP recupera una sorgente per IP
func (p *TrustedSourcePolicy) GetSourceByIP(ip string) *TrustedSource {
	p.sourcesLock.RLock()
	defer p.sourcesLock.RUnlock()

	// First try exact match
	if source, exists := p.Sources[ip]; exists {
		return source
	}

	// Try CIDR match
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	for _, source := range p.Sources {
		if source.IPRange == "" {
			continue
		}

		_, ipnet, err := net.ParseCIDR(source.IPRange)
		if err != nil {
			continue
		}

		if ipnet.Contains(parsedIP) && source.IsEnabled {
			return source
		}
	}

	return nil
}

// GetSourceByID recupera una sorgente per ID
func (p *TrustedSourcePolicy) GetSourceByID(id string) *TrustedSource {
	p.sourcesLock.RLock()
	defer p.sourcesLock.RUnlock()

	for _, source := range p.Sources {
		if source.ID == id {
			return source
		}
	}
	return nil
}

// ListSources ritorna tutte le sorgenti trusted
func (p *TrustedSourcePolicy) ListSources() []*TrustedSource {
	p.sourcesLock.RLock()
	defer p.sourcesLock.RUnlock()

	sources := make([]*TrustedSource, 0, len(p.Sources))
	for _, source := range p.Sources {
		sources = append(sources, source)
	}
	return sources
}

// IsTrustedByPolicy controlla se un IP è trusted secondo la policy
func (p *TrustedSourcePolicy) IsTrustedByPolicy(ip string) bool {
	if !p.IsEnabled {
		return false
	}

	source := p.GetSourceByIP(ip)
	return source != nil && source.IsEnabled
}

// VerifySourceValidity controlla se una sorgente è valida
func (p *TrustedSourcePolicy) VerifySourceValidity(ip string) (bool, string) {
	source := p.GetSourceByIP(ip)
	if source == nil {
		return false, "Source not found in policy"
	}

	if !source.IsEnabled {
		return false, "Source is disabled"
	}

	if source.CurrentErrorCount >= source.BlockedAfterErrors && source.BlockedAfterErrors > 0 {
		return false, "Source blocked due to validation errors"
	}

	return true, ""
}

// RecordSourceError registra un errore di validazione per una sorgente
func (p *TrustedSourcePolicy) RecordSourceError(ip string) {
	source := p.GetSourceByIP(ip)
	if source == nil {
		return
	}

	p.sourcesLock.Lock()
	defer p.sourcesLock.Unlock()

	source.CurrentErrorCount++

	if p.AutoBlockOnErrors && source.BlockedAfterErrors > 0 && source.CurrentErrorCount >= source.BlockedAfterErrors {
		source.IsEnabled = false
	}
}

// ResetSourceErrors resetta il counter errori per una sorgente
func (p *TrustedSourcePolicy) ResetSourceErrors(ip string) {
	source := p.GetSourceByIP(ip)
	if source == nil {
		return
	}

	p.sourcesLock.Lock()
	defer p.sourcesLock.Unlock()

	source.CurrentErrorCount = 0
}

// GlobalTrustedSourceManager gestisce multiple policy globalmente
type GlobalTrustedSourceManager struct {
	policies     map[string]*TrustedSourcePolicy
	policiesLock sync.RWMutex
	defaultPolicy *TrustedSourcePolicy
}

// NewGlobalTrustedSourceManager crea un nuovo manager globale
func NewGlobalTrustedSourceManager() *GlobalTrustedSourceManager {
	return &GlobalTrustedSourceManager{
		policies: make(map[string]*TrustedSourcePolicy),
	}
}

// AddPolicy aggiunge una nuova policy al manager
func (m *GlobalTrustedSourceManager) AddPolicy(policy *TrustedSourcePolicy) {
	m.policiesLock.Lock()
	defer m.policiesLock.Unlock()

	m.policies[policy.ID] = policy

	if policy.IsDefault {
		m.defaultPolicy = policy
	}
}

// GetPolicy recupera una policy per ID
func (m *GlobalTrustedSourceManager) GetPolicy(id string) *TrustedSourcePolicy {
	m.policiesLock.RLock()
	defer m.policiesLock.RUnlock()

	return m.policies[id]
}

// GetDefaultPolicy ritorna la default policy
func (m *GlobalTrustedSourceManager) GetDefaultPolicy() *TrustedSourcePolicy {
	m.policiesLock.RLock()
	defer m.policiesLock.RUnlock()

	return m.defaultPolicy
}

// IsTrusted controlla se un IP è trusted da qualsiasi policy abilitata
func (m *GlobalTrustedSourceManager) IsTrusted(ip string) bool {
	m.policiesLock.RLock()
	defer m.policiesLock.RUnlock()

	for _, policy := range m.policies {
		if policy.IsEnabled && policy.IsTrustedByPolicy(ip) {
			return true
		}
	}

	return false
}

// CreateDefaultPolicy crea una policy di default enterprise
func CreateDefaultPolicy() *TrustedSourcePolicy {
	policy := NewTrustedSourcePolicy("default", "Default Enterprise Policy")
	policy.IsDefault = true
	policy.DefaultTrustLevel = "low"
	policy.RequireSignature = true
	policy.EnableDMZDetection = true
	policy.EnableTailscaleDetection = true

	// Localhost trusted by default
	policy.AddSource(&TrustedSource{
		ID:                  "localhost",
		Name:                "Localhost",
		Type:                SourceTypeCustom,
		IP:                  "127.0.0.1",
		IsEnabled:           true,
		TrustsXPublicIP:     true,
		TrustsXForwardedFor: true,
		TrustsXRealIP:       true,
		RequireSignature:    false,
	})

	// IPv6 localhost
	policy.AddSource(&TrustedSource{
		ID:                  "localhost-ipv6",
		Name:                "Localhost IPv6",
		Type:                SourceTypeCustom,
		IP:                  "::1",
		IsEnabled:           true,
		TrustsXPublicIP:     true,
		TrustsXForwardedFor: true,
		TrustsXRealIP:       true,
		RequireSignature:    false,
	})

	return policy
}

// ExtendedSourceValidationInfo contiene info dettagliata di validazione di una sorgente
type ExtendedSourceValidationInfo struct {
	IP                   string
	SourceType           string
	IsTrusted            bool
	ValidationTimestamp  time.Time
	Policy               string // ID della policy che ha validato
	Source               *TrustedSource
	TrustLevel           string // "critical", "high", "medium", "low", "none"
	RiskFactors          []string
	RecommendedActions   []string
}

// ValidateSourceComprehensive esegue una validazione completa di una sorgente
func ValidateSourceComprehensive(
	ip string,
	manager *GlobalTrustedSourceManager,
	dmzConfig *DMZDetectionConfig,
	tsConfig *TailscaleDetectionConfig,
) *ExtendedSourceValidationInfo {
	info := &ExtendedSourceValidationInfo{
		IP:                  ip,
		ValidationTimestamp: time.Now(),
		IsTrusted:           manager.IsTrusted(ip),
		RiskFactors:         []string{},
		RecommendedActions:  []string{},
	}

	// Classifica il tipo di sorgente
	if IsDMZIP(ip, dmzConfig) {
		info.SourceType = "dmz"
		info.TrustLevel = "high"
	} else if IsTailscaleIP(ip, tsConfig) {
		info.SourceType = "tailscale"
		if info.IsTrusted {
			info.TrustLevel = "high"
		} else {
			info.TrustLevel = "medium"
			info.RiskFactors = append(info.RiskFactors, "Tailscale IP but not in trusted sources")
		}
	} else if info.IsTrusted {
		info.SourceType = "trusted_proxy"
		info.TrustLevel = "high"
	} else if isPrivateIP(ip) {
		info.SourceType = "private"
		info.TrustLevel = "medium"
		info.RiskFactors = append(info.RiskFactors, "Private IP, might be spoofed")
	} else {
		info.SourceType = "public"
		info.TrustLevel = "low"
		info.RiskFactors = append(info.RiskFactors, "Public IP, high spoofing risk")
		info.RecommendedActions = append(info.RecommendedActions, "Require HMAC signature")
	}

	// Aggiungi dettagli della sorgente se trovata
	defaultPolicy := manager.GetDefaultPolicy()
	if defaultPolicy != nil {
		info.Policy = defaultPolicy.ID
		source := defaultPolicy.GetSourceByIP(ip)
		if source != nil {
			info.Source = source
		}
	}

	return info
}
