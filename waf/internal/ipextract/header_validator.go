package ipextract

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HeaderSignatureConfig contiene la configurazione per la validazione delle firme HMAC
type HeaderSignatureConfig struct {
	Enabled              bool
	SharedSecret         string        // Secret HMAC condiviso con proxy/trusted sources
	MaxClockSkew         time.Duration // Massimo scostamento orario tollerato
	RequireSignature     bool          // Se true, manca firma = reject
	HeaderName           string        // Nome custom per header firma (default: X-HMAC-Signature)
	TimestampHeaderName  string        // Nome custom per header timestamp
	IncludeHeadersInSig  []string      // Headers da includere nella firma (oltre al payload)
}

// HeaderValidationResult contiene il risultato della validazione di una firma header
type HeaderValidationResult struct {
	IsValid           bool
	IsTrustedSource   bool
	SignatureMatch    bool
	TimestampValid    bool
	ErrorMessage      string
	ValidationDetails string
}

// DefaultHeaderSignatureConfig ritorna una config di default sicura
func DefaultHeaderSignatureConfig() *HeaderSignatureConfig {
	return &HeaderSignatureConfig{
		Enabled:             false,
		SharedSecret:        "",
		MaxClockSkew:        30 * time.Second,
		RequireSignature:    false,
		HeaderName:          "X-HMAC-Signature",
		TimestampHeaderName: "X-Request-Timestamp",
		IncludeHeadersInSig: []string{"X-Public-IP", "X-Forwarded-For", "X-Real-IP"},
	}
}

// ValidateHeaderSignature valida la firma HMAC di un header X-Public-IP
// Questo previene lo spoofing di IP da fonti non autorizzate
//
// Processo:
// 1. Verifica che il timestamp sia recente (entro MaxClockSkew)
// 2. Ricostruisce la firma dal payload
// 3. Confronta con X-HMAC-Signature header
// 4. Verifica che la richiesta provenga da una trusted source
func ValidateHeaderSignature(
	r *http.Request,
	config *HeaderSignatureConfig,
	remoteIP string,
) *HeaderValidationResult {
	result := &HeaderValidationResult{
		IsValid:         true,
		IsTrustedSource: false,
		SignatureMatch:  false,
		TimestampValid:  false,
	}

	// Se disabled, skip validation
	if !config.Enabled {
		result.IsValid = true
		result.ValidationDetails = "Signature validation disabled"
		return result
	}

	// Se non required e manca firma, allow
	if !config.RequireSignature {
		xPublicIP := r.Header.Get("X-Public-IP")
		xSignature := r.Header.Get(config.HeaderName)

		if xPublicIP != "" && xSignature == "" {
			result.IsValid = true
			result.ValidationDetails = "Signature not required, but IP header present"
			return result
		}
	}

	// Get header values
	xPublicIP := r.Header.Get("X-Public-IP")
	xTimestamp := r.Header.Get(config.TimestampHeaderName)
	xSignature := r.Header.Get(config.HeaderName)

	// Se c'è firma, deve essere valida
	if xSignature != "" {
		// Validazione timestamp
		if xTimestamp == "" {
			result.IsValid = false
			result.ErrorMessage = "Signature present but timestamp missing"
			return result
		}

		// Parse timestamp
		tsInt, err := strconv.ParseInt(xTimestamp, 10, 64)
		if err != nil {
			result.IsValid = false
			result.ErrorMessage = fmt.Sprintf("Invalid timestamp format: %v", err)
			return result
		}

		requestTime := time.Unix(tsInt, 0)
		now := time.Now()
		skew := now.Sub(requestTime)
		if skew < 0 {
			skew = -skew
		}

		// Controlla clock skew
		if skew > config.MaxClockSkew {
			result.IsValid = false
			result.TimestampValid = false
			result.ErrorMessage = fmt.Sprintf("Timestamp outside acceptable skew (skew: %v, max: %v)", skew, config.MaxClockSkew)
			return result
		}

		result.TimestampValid = true

		// Verifica firma
		// Payload per firma: IP|timestamp|method|path
		payload := buildSignaturePayload(xPublicIP, xTimestamp, r.Method, r.URL.Path, r, config)
		expectedSignature := computeHMACSignature(payload, config.SharedSecret)

		// Constant-time comparison per evitare timing attacks
		if !hmac.Equal([]byte(xSignature), []byte(expectedSignature)) {
			result.IsValid = false
			result.SignatureMatch = false
			result.ErrorMessage = "Signature mismatch"
			result.ValidationDetails = fmt.Sprintf("Expected: %s, Got: %s", expectedSignature[:16]+"...", xSignature[:16]+"...")
			return result
		}

		result.SignatureMatch = true
	}

	// Verifica che il remote IP sia trusted (se firma è presente/valida)
	if xSignature != "" && xPublicIP != "" {
		if !isTrustedProxy(remoteIP) {
			result.IsValid = false
			result.IsTrustedSource = false
			result.ErrorMessage = fmt.Sprintf("Request from non-trusted source IP: %s", remoteIP)
			return result
		}
		result.IsTrustedSource = true
	}

	result.IsValid = true
	result.ValidationDetails = "Header signature validation passed"
	return result
}

// buildSignaturePayload costruisce il payload da firmare
func buildSignaturePayload(ip string, timestamp string, method string, path string, r *http.Request, config *HeaderSignatureConfig) string {
	parts := []string{ip, timestamp, method, path}

	// Aggiungi altri header se configurato
	for _, headerName := range config.IncludeHeadersInSig {
		if val := r.Header.Get(headerName); val != "" {
			parts = append(parts, fmt.Sprintf("%s:%s", headerName, val))
		}
	}

	return strings.Join(parts, "|")
}

// computeHMACSignature calcola la firma HMAC-SHA256
func computeHMACSignature(payload string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateClientSignature genera una firma HMAC per il client da includere nella richiesta
// Usato da client (es. Tailscale) per auto-firmare il loro IP pubblico
func GenerateClientSignature(ip string, secret string, additionalHeaders map[string]string) (signature string, timestamp string) {
	timestamp = fmt.Sprintf("%d", time.Now().Unix())

	// Payload: IP|timestamp|additional_headers
	parts := []string{ip, timestamp}
	for key, val := range additionalHeaders {
		parts = append(parts, fmt.Sprintf("%s:%s", key, val))
	}
	payload := strings.Join(parts, "|")

	signature = computeHMACSignature(payload, secret)
	return
}

// ValidateTrustedHeaderSource valida che un header provvenga da una fonte trusted
// Combina validazione firma + IP source + whitelist per massima sicurezza
func ValidateTrustedHeaderSource(
	r *http.Request,
	remoteIP string,
	config *HeaderSignatureConfig,
	trustedSources *TrustedSourcePolicy,
) bool {
	// 1. Verifica firma se abilitata
	if config.Enabled {
		result := ValidateHeaderSignature(r, config, remoteIP)
		if !result.IsValid {
			return false
		}
	}

	// 2. Verifica che il source IP sia nel whitelist dei trusted
	if !isTrustedProxy(remoteIP) {
		return false
	}

	// 3. Se c'è una policy di trusted sources, verifica lì
	if trustedSources != nil {
		source := trustedSources.GetSourceByIP(remoteIP)
		if source == nil || !source.IsEnabled {
			return false
		}
	}

	return true
}

// DMZDetectionConfig contiene la configurazione per il riconoscimento della DMZ
type DMZDetectionConfig struct {
	Enabled     bool
	DMZNetworks []string // CIDR ranges per la DMZ (es: "192.168.100.0/24")
}

// IsDMZIP controlla se un IP è nella DMZ
func IsDMZIP(ip string, dmzConfig *DMZDetectionConfig) bool {
	if !dmzConfig.Enabled {
		return false
	}

	for _, cidr := range dmzConfig.DMZNetworks {
		if IsIPInRange(ip, cidr) {
			return true
		}
	}
	return false
}

// TailscaleDetectionConfig contiene i range IP di Tailscale
type TailscaleDetectionConfig struct {
	Enabled               bool
	TailscaleNetworks     []string // CIDR ranges di Tailscale (es: "100.64.0.0/10")
	VerifyHeaderSignature bool     // Se true, richiede firma HMAC per X-Public-IP
}

// IsTailscaleIP controlla se un IP è un Tailscale IP
func IsTailscaleIP(ip string, tsConfig *TailscaleDetectionConfig) bool {
	if !tsConfig.Enabled {
		return false
	}

	for _, cidr := range tsConfig.TailscaleNetworks {
		if IsIPInRange(ip, cidr) {
			return true
		}
	}
	return false
}

// EnhancedClientIPInfo estende ClientIPInfo con dati enterprise
type EnhancedClientIPInfo struct {
	*ClientIPInfo

	// Source classification
	SourceType          string // "public", "private", "tailscale", "dmz", "proxy"
	SourceClassification string // "trusted", "untrusted", "suspicious"

	// Trust metadata
	HeaderSignatureValid bool
	DMZIP                bool
	TailscaleIP          bool
	TrustedSourcePolicy  string // Nome della policy applicata

	// Risk scoring
	TrustScore int // 0-100: 100=fully trusted, 0=completely untrusted

	// Audit
	ValidationTimestamp time.Time
	ValidationDetails   string
}

// ComputeTrustScore calcola un trust score per l'IP (0-100)
// Basato su: source type, signature validation, whitelist status, ecc.
func ComputeTrustScore(
	info *ClientIPInfo,
	headerSigValid bool,
	isDMZ bool,
	isTailscale bool,
	isWhitelisted bool,
) int {
	score := 50 // Base score: neutral

	// Aumenta se è IP pubblico diretto (meno spoofabile)
	if info.IsPublicIP && info.Source == SourceRemoteAddr {
		score += 20
	}

	// Aumenta se viene da proxy trusted
	if info.IsTrusted && (info.Source == SourceXForwardedFor || info.Source == SourceXRealIP) {
		score += 15
	}

	// Aumenta se Tailscale con firma valida
	if isTailscale && headerSigValid {
		score += 20
	}

	// Aumenta se DMZ
	if isDMZ {
		score += 10
	}

	// Aumenta se in whitelist
	if isWhitelisted {
		score += 10
	}

	// Penalizza se X-Public-IP senza firma
	if info.Source == SourceXPublicIP && !headerSigValid {
		score -= 15
	}

	// Penalizza IP privati sospetti
	if info.IsPrivateIP && info.Source == SourceXPublicIP {
		score -= 20
	}

	// Clamp tra 0 e 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
