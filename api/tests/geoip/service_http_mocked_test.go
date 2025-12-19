package geoip

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	logger.InitLogger("error", "/dev/null")
}

// MockHTTPClient for testing
type MockHTTPClient struct {
	GetFunc func(url string) (*http.Response, error)
}

func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	if m.GetFunc != nil {
		return m.GetFunc(url)
	}
	return nil, errors.New("GetFunc not set")
}

// Test EnrichIPFromService with HTTP GET error
func TestEnrichIPFromService_HTTPGetError(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return nil, errors.New("network error")
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	// Should return Unknown on HTTP error
	country := service.EnrichIPFromService("8.8.8.8")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with HTTP 404 response
func TestEnrichIPFromService_HTTP404(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewReader([]byte("Not found"))),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("1.2.3.4")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with HTTP 500 error
func TestEnrichIPFromService_HTTP500(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewReader([]byte("Server error"))),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("1.2.3.4")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with invalid JSON response
func TestEnrichIPFromService_InvalidJSON(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte("{invalid json}"))),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("1.2.3.4")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with missing country_name in response
func TestEnrichIPFromService_MissingCountryName(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			response := map[string]interface{}{
				"ip":   "1.2.3.4",
				"city": "Test City",
				// No country_name field
			}
			data, _ := json.Marshal(response)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("1.2.3.4")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with empty country_name
func TestEnrichIPFromService_EmptyCountryName(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			response := map[string]interface{}{
				"ip":           "1.2.3.4",
				"country_name": "", // Empty country name
			}
			data, _ := json.Marshal(response)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("1.2.3.4")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with successful mocked response
func TestEnrichIPFromService_MockedSuccess(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			response := map[string]interface{}{
				"ip":           "8.8.8.8",
				"country_name": "United States",
				"country":      "US",
				"city":         "Mountain View",
			}
			data, _ := json.Marshal(response)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("8.8.8.8")
	assert.Equal(t, "United States", country)
}

// Test EnrichIPFromService with different country names
func TestEnrichIPFromService_DifferentCountries(t *testing.T) {
	testCases := []struct {
		ip          string
		countryName string
	}{
		{"8.8.8.8", "United States"},
		{"1.1.1.1", "Australia"},
		{"77.88.8.8", "Russia"},
		{"114.114.114.114", "China"},
	}

	for _, tc := range testCases {
		t.Run(tc.countryName, func(t *testing.T) {
			mockHTTP := &MockHTTPClient{
				GetFunc: func(url string) (*http.Response, error) {
					response := map[string]interface{}{
						"ip":           tc.ip,
						"country_name": tc.countryName,
					}
					data, _ := json.Marshal(response)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(data)),
					}, nil
				},
			}

			service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
			require.NoError(t, err)

			country := service.EnrichIPFromService(tc.ip)
			assert.Equal(t, tc.countryName, country)
		})
	}
}

// Test EnrichIPFromService with ReadAll error
type mockedErrorReader struct{}

func (e *mockedErrorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestEnrichIPFromService_MockedReadAllError(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(&mockedErrorReader{}),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("8.8.8.8")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with malformed country_name (not string)
func TestEnrichIPFromService_CountryNameNotString(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			response := map[string]interface{}{
				"ip":           "8.8.8.8",
				"country_name": 123, // Number instead of string
			}
			data, _ := json.Marshal(response)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("8.8.8.8")
	assert.Equal(t, "Unknown", country)
}

// Test EnrichIPFromService with private IP (should skip HTTP call)
func TestEnrichIPFromService_PrivateIPNoHTTPCall(t *testing.T) {
	httpCalled := false
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			httpCalled = true
			return nil, errors.New("should not be called")
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("192.168.1.1")
	assert.Equal(t, "Unknown", country)
	assert.False(t, httpCalled, "HTTP should not be called for private IP")
}

// Test EnrichIPFromService with invalid IP format (should skip HTTP call)
func TestEnrichIPFromService_InvalidIPNoHTTPCall(t *testing.T) {
	httpCalled := false
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			httpCalled = true
			return nil, errors.New("should not be called")
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("invalid-ip")
	assert.Equal(t, "Unknown", country)
	assert.False(t, httpCalled, "HTTP should not be called for invalid IP")
}

// Test EnrichIPFromService with very large mocked JSON response
func TestEnrichIPFromService_MockedLargeResponse(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			response := map[string]interface{}{
				"ip":           "8.8.8.8",
				"country_name": "United States",
				"extra_large_field": make([]byte, 100000), // 100KB of data
			}
			data, _ := json.Marshal(response)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	country := service.EnrichIPFromService("8.8.8.8")
	assert.Equal(t, "United States", country)
}

// Test that NewServiceWithHTTPClient maintains service functionality
func TestNewServiceWithHTTPClient_FullFunctionality(t *testing.T) {
	mockHTTP := &MockHTTPClient{
		GetFunc: func(url string) (*http.Response, error) {
			response := map[string]interface{}{
				"ip":           "8.8.8.8",
				"country_name": "Test Country",
			}
			data, _ := json.Marshal(response)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		},
	}

	service, err := geoip.NewServiceWithHTTPClient(mockHTTP)
	require.NoError(t, err)

	// Test LookupCountry still works
	country := service.LookupCountry("1.1.1.1")
	assert.NotEmpty(t, country)

	// Test enrichment works
	enriched := service.EnrichIPFromService("8.8.8.8")
	assert.Equal(t, "Test Country", enriched)

	// Test LookupCountryWithEnrichment works
	countryWithEnrich := service.LookupCountryWithEnrichment("8.8.8.8")
	assert.NotEmpty(t, countryWithEnrich)
}
