package ipextract

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestHMACSignatureValidation(t *testing.T) {
	// Test 1: Valid HMAC signature
	t.Run("valid_hmac_signature", func(t *testing.T) {
		config := &HeaderSignatureConfig{
			Enabled:             true,
			SharedSecret:        "test-secret-key",
			MaxClockSkew:        30 * time.Second,
			RequireSignature:    true,
			HeaderName:          "X-HMAC-Signature",
			TimestampHeaderName: "X-Request-Timestamp",
		}

		// Generate timestamp
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)

		// Generate signature
		signature, _ := GenerateClientSignature("203.0.113.45", "test-secret-key", map[string]string{})

		// Create request
		req, _ := http.NewRequest("GET", "http://example.com/api", nil)
		req.Header.Set("X-Public-IP", "203.0.113.45")
		req.Header.Set(config.HeaderName, signature)
		req.Header.Set(config.TimestampHeaderName, timestamp)

		// Validate
		result := ValidateHeaderSignature(req, config, "10.0.1.5")

		if !result.IsValid {
			t.Errorf("Expected valid signature, got error: %s", result.ErrorMessage)
		}
	})

	// Test 2: Invalid timestamp (clock skew)
	t.Run("invalid_timestamp_skew", func(t *testing.T) {
		config := &HeaderSignatureConfig{
			Enabled:             true,
			SharedSecret:        "test-secret-key",
			MaxClockSkew:        10 * time.Second,
			RequireSignature:    true,
			HeaderName:          "X-HMAC-Signature",
			TimestampHeaderName: "X-Request-Timestamp",
		}

		// Generate old timestamp (more than maxClockSkew)
		oldTime := time.Now().Add(-30 * time.Second)
		timestamp := strconv.FormatInt(oldTime.Unix(), 10)

		// Generate signature
		signature := computeHMACSignature("203.0.113.45|"+timestamp+"|GET|/api", "test-secret-key")

		// Create request
		req, _ := http.NewRequest("GET", "http://example.com/api", nil)
		req.Header.Set("X-Public-IP", "203.0.113.45")
		req.Header.Set(config.HeaderName, signature)
		req.Header.Set(config.TimestampHeaderName, timestamp)

		// Validate
		result := ValidateHeaderSignature(req, config, "10.0.1.5")

		if result.IsValid {
			t.Error("Expected invalid timestamp, but validation passed")
		}
		if !result.TimestampValid {
			t.Log("Correctly detected invalid timestamp skew")
		}
	})

	// Test 3: Signature mismatch
	t.Run("signature_mismatch", func(t *testing.T) {
		config := &HeaderSignatureConfig{
			Enabled:             true,
			SharedSecret:        "test-secret-key",
			MaxClockSkew:        30 * time.Second,
			RequireSignature:    true,
			HeaderName:          "X-HMAC-Signature",
			TimestampHeaderName: "X-Request-Timestamp",
		}

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)

		// Create request with wrong signature
		req, _ := http.NewRequest("GET", "http://example.com/api", nil)
		req.Header.Set("X-Public-IP", "203.0.113.45")
		req.Header.Set(config.HeaderName, "wrong-signature-value")
		req.Header.Set(config.TimestampHeaderName, timestamp)

		// Validate
		result := ValidateHeaderSignature(req, config, "10.0.1.5")

		if result.IsValid {
			t.Error("Expected invalid signature, but validation passed")
		}
		if !result.SignatureMatch {
			t.Log("Correctly detected signature mismatch")
		}
	})

	// Test 4: Missing timestamp
	t.Run("missing_timestamp", func(t *testing.T) {
		config := &HeaderSignatureConfig{
			Enabled:             true,
			SharedSecret:        "test-secret-key",
			MaxClockSkew:        30 * time.Second,
			RequireSignature:    true,
			HeaderName:          "X-HMAC-Signature",
			TimestampHeaderName: "X-Request-Timestamp",
		}

		// Create request without timestamp
		req, _ := http.NewRequest("GET", "http://example.com/api", nil)
		req.Header.Set("X-Public-IP", "203.0.113.45")
		req.Header.Set(config.HeaderName, "some-signature")

		// Validate
		result := ValidateHeaderSignature(req, config, "10.0.1.5")

		if result.IsValid {
			t.Error("Expected invalid (missing timestamp), but validation passed")
		}
	})

	// Test 5: Signature validation disabled
	t.Run("validation_disabled", func(t *testing.T) {
		config := &HeaderSignatureConfig{
			Enabled:             false,
			SharedSecret:        "test-secret-key",
			MaxClockSkew:        30 * time.Second,
			RequireSignature:    false,
			HeaderName:          "X-HMAC-Signature",
			TimestampHeaderName: "X-Request-Timestamp",
		}

		req, _ := http.NewRequest("GET", "http://example.com/api", nil)
		req.Header.Set("X-Public-IP", "203.0.113.45")

		// Validate
		result := ValidateHeaderSignature(req, config, "10.0.1.5")

		if !result.IsValid {
			t.Error("Expected valid when validation disabled")
		}
	})
}

func TestDMZDetection(t *testing.T) {
	config := &DMZDetectionConfig{
		Enabled:     true,
		DMZNetworks: []string{"192.168.100.0/24", "10.0.1.0/24"},
	}

	t.Run("dmz_ip_detected", func(t *testing.T) {
		if !IsDMZIP("192.168.100.42", config) {
			t.Error("Expected 192.168.100.42 to be detected as DMZ IP")
		}
		if !IsDMZIP("10.0.1.5", config) {
			t.Error("Expected 10.0.1.5 to be detected as DMZ IP")
		}
	})

	t.Run("non_dmz_ip", func(t *testing.T) {
		if IsDMZIP("203.0.113.45", config) {
			t.Error("Expected 203.0.113.45 to NOT be detected as DMZ IP")
		}
	})

	t.Run("dmz_detection_disabled", func(t *testing.T) {
		disabledConfig := &DMZDetectionConfig{
			Enabled:     false,
			DMZNetworks: []string{"192.168.100.0/24"},
		}
		if IsDMZIP("192.168.100.42", disabledConfig) {
			t.Error("Expected detection to be disabled")
		}
	})
}

func TestTailscaleDetection(t *testing.T) {
	config := &TailscaleDetectionConfig{
		Enabled:           true,
		TailscaleNetworks: []string{"100.64.0.0/10"},
	}

	t.Run("tailscale_ip_detected", func(t *testing.T) {
		if !IsTailscaleIP("100.64.1.42", config) {
			t.Error("Expected 100.64.1.42 to be detected as Tailscale IP")
		}
		if !IsTailscaleIP("100.127.255.255", config) {
			t.Error("Expected 100.127.255.255 to be detected as Tailscale IP")
		}
	})

	t.Run("non_tailscale_ip", func(t *testing.T) {
		if IsTailscaleIP("203.0.113.45", config) {
			t.Error("Expected 203.0.113.45 to NOT be detected as Tailscale IP")
		}
	})

	t.Run("tailscale_detection_disabled", func(t *testing.T) {
		disabledConfig := &TailscaleDetectionConfig{
			Enabled:           false,
			TailscaleNetworks: []string{"100.64.0.0/10"},
		}
		if IsTailscaleIP("100.64.1.42", disabledConfig) {
			t.Error("Expected detection to be disabled")
		}
	})
}

func TestTrustScoreCalculation(t *testing.T) {
	baseInfo := &ClientIPInfo{
		IP:             "203.0.113.45",
		IsPublicIP:     true,
		IsPrivateIP:    false,
		Source:         SourceRemoteAddr,
		IsTrusted:      true,
		IsVPNTailscale: false,
	}

	t.Run("full_trust_score", func(t *testing.T) {
		// Tailscale IP with valid signature, whitelisted
		score := ComputeTrustScore(baseInfo, true, false, true, true)
		if score < 80 {
			t.Errorf("Expected high trust score for fully trusted source, got %d", score)
		}
	})

	t.Run("low_trust_score", func(t *testing.T) {
		// Public IP without signature, not whitelisted
		score := ComputeTrustScore(baseInfo, false, false, false, false)
		if score > 60 {
			t.Errorf("Expected low trust score for untrusted source, got %d", score)
		}
	})

	t.Run("medium_trust_score", func(t *testing.T) {
		// DMZ IP without special properties
		score := ComputeTrustScore(baseInfo, false, true, false, false)
		if score < 40 || score > 70 {
			t.Errorf("Expected medium trust score for DMZ IP, got %d", score)
		}
	})
}

func TestEnhancedIPInfoCompilation(t *testing.T) {
	config := &DMZDetectionConfig{
		Enabled:     true,
		DMZNetworks: []string{"10.0.1.0/24"},
	}

	tsConfig := &TailscaleDetectionConfig{
		Enabled:           true,
		TailscaleNetworks: []string{"100.64.0.0/10"},
	}

	t.Run("dmz_ip_classification", func(t *testing.T) {
		info := &ClientIPInfo{
			IP:             "10.0.1.5",
			IsPublicIP:     false,
			IsPrivateIP:    true,
			Source:         SourceXForwardedFor,
			IsTrusted:      true,
			IsVPNTailscale: false,
		}

		isDMZ := IsDMZIP(info.IP, config)
		isTailscale := IsTailscaleIP(info.IP, tsConfig)
		score := ComputeTrustScore(info, false, isDMZ, isTailscale, false)

		if !isDMZ {
			t.Error("Expected IP to be classified as DMZ")
		}
		if score < 50 {
			t.Errorf("Expected reasonable trust score for DMZ, got %d", score)
		}
	})

	t.Run("tailscale_ip_classification", func(t *testing.T) {
		info := &ClientIPInfo{
			IP:             "100.64.1.42",
			IsPublicIP:     false,
			IsPrivateIP:    false,
			Source:         SourceXPublicIP,
			IsTrusted:      false,
			IsVPNTailscale: true,
		}

		isDMZ := IsDMZIP(info.IP, config)
		isTailscale := IsTailscaleIP(info.IP, tsConfig)

		if isDMZ {
			t.Error("Expected IP to NOT be classified as DMZ")
		}
		if !isTailscale {
			t.Error("Expected IP to be classified as Tailscale")
		}
	})
}

func BenchmarkHMACValidation(b *testing.B) {
	config := &HeaderSignatureConfig{
		Enabled:             true,
		SharedSecret:        "test-secret-key",
		MaxClockSkew:        30 * time.Second,
		RequireSignature:    true,
		HeaderName:          "X-HMAC-Signature",
		TimestampHeaderName: "X-Request-Timestamp",
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := computeHMACSignature("203.0.113.45|"+timestamp+"|GET|/api", "test-secret-key")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/api", nil)
		req.Header.Set("X-Public-IP", "203.0.113.45")
		req.Header.Set(config.HeaderName, signature)
		req.Header.Set(config.TimestampHeaderName, timestamp)

		ValidateHeaderSignature(req, config, "10.0.1.5")
	}
}

func BenchmarkIPDetection(b *testing.B) {
	dmzConfig := &DMZDetectionConfig{
		Enabled:     true,
		DMZNetworks: []string{"10.0.0.0/8"},
	}

	tsConfig := &TailscaleDetectionConfig{
		Enabled:           true,
		TailscaleNetworks: []string{"100.64.0.0/10"},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		IsDMZIP("10.0.1.5", dmzConfig)
		IsTailscaleIP("100.64.1.42", tsConfig)
		ComputeTrustScore(&ClientIPInfo{}, false, true, false, false)
	}
}
