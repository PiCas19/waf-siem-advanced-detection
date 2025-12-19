package helpers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTestContext(queryParams map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Creiamo una richiesta HTTP valida
	req, _ := http.NewRequest("GET", "/test", nil)
	
	// Aggiungiamo i parametri query
	q := req.URL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()
	
	c.Request = req

	return c
}

func TestParsePaginationParams(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    map[string]string
		expectedLimit  int
		expectedOffset int
		expectedSort   string
		expectedOrder  string
		expectError    bool
	}{
		{
			name:           "Default values",
			queryParams:    map[string]string{},
			expectedLimit:  20,
			expectedOffset: 0,
			expectedSort:   "",
			expectedOrder:  "asc",
			expectError:    false,
		},
		{
			name: "Custom valid values",
			queryParams: map[string]string{
				"limit":  "50",
				"offset": "100",
				"sort":   "name",
				"order":  "desc",
			},
			expectedLimit:  50,
			expectedOffset: 100,
			expectedSort:   "name",
			expectedOrder:  "desc",
			expectError:    false,
		},
		{
			name: "Limit too high",
			queryParams: map[string]string{
				"limit": "200",
			},
			expectedLimit:  100,
			expectedOffset: 0,
			expectedSort:   "",
			expectedOrder:  "asc",
			expectError:    false,
		},
		{
			name: "Limit too low",
			queryParams: map[string]string{
				"limit": "0",
			},
			expectedLimit:  1,
			expectedOffset: 0,
			expectedSort:   "",
			expectedOrder:  "asc",
			expectError:    false,
		},
		{
			name: "Negative offset",
			queryParams: map[string]string{
				"offset": "-10",
			},
			expectedLimit:  20,
			expectedOffset: 0,
			expectedSort:   "",
			expectedOrder:  "asc",
			expectError:    false,
		},
		{
			name: "Invalid limit type",
			queryParams: map[string]string{
				"limit": "not-a-number",
			},
			expectError: true,
		},
		{
			name: "Invalid offset type",
			queryParams: map[string]string{
				"offset": "not-a-number",
			},
			expectError: true,
		},
		{
			name: "Invalid order",
			queryParams: map[string]string{
				"order": "invalid",
			},
			expectedLimit:  20,
			expectedOffset: 0,
			expectedSort:   "",
			expectedOrder:  "asc",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := setupTestContext(tt.queryParams)
			limit, offset, sort, order, err := helpers.ParsePaginationParams(c)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedLimit, limit)
				assert.Equal(t, tt.expectedOffset, offset)
				assert.Equal(t, tt.expectedSort, sort)
				assert.Equal(t, tt.expectedOrder, order)
			}
		})
	}
}

func TestParsePaginationParamsWithDefaults(t *testing.T) {
	tests := []struct {
		name           string
		defaultLimit   int
		queryParams    map[string]string
		expectedLimit  int
		expectedOffset int
		expectError    bool
	}{
		{
			name:         "Use default limit",
			defaultLimit: 30,
			queryParams:  map[string]string{},
			expectedLimit: 30,
			expectError:  false,
		},
		{
			name:         "Override default limit",
			defaultLimit: 30,
			queryParams: map[string]string{
				"limit": "40",
			},
			expectedLimit: 40,
			expectError:  false,
		},
		{
			name:         "Default too high",
			defaultLimit: 150,
			queryParams:  map[string]string{},
			expectedLimit: 100,
			expectError:  false,
		},
		{
			name:         "Default too low",
			defaultLimit: 0,
			queryParams:  map[string]string{},
			expectedLimit: 1,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := setupTestContext(tt.queryParams)
			limit, offset, _, _, err := helpers.ParsePaginationParamsWithDefaults(c, tt.defaultLimit)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedLimit, limit)
				assert.Equal(t, 0, offset) // Default offset should be 0
			}
		})
	}
}

func TestBuildPaginationInfo(t *testing.T) {
	tests := []struct {
		name           string
		limit          int
		offset         int
		total          int64
		expectedPage   int
		expectedTotal  int64
		expectedHasNext bool
		expectedHasPrev bool
	}{
		{
			name:           "First page",
			limit:          20,
			offset:         0,
			total:          100,
			expectedPage:   1,
			expectedTotal:  100,
			expectedHasNext: true,
			expectedHasPrev: false,
		},
		{
			name:           "Second page",
			limit:          20,
			offset:         20,
			total:          100,
			expectedPage:   2,
			expectedTotal:  100,
			expectedHasNext: true,
			expectedHasPrev: true,
		},
		{
			name:           "Last page",
			limit:          20,
			offset:         80,
			total:          100,
			expectedPage:   5,
			expectedTotal:  100,
			expectedHasNext: false,
			expectedHasPrev: true,
		},
		{
			name:           "Empty results",
			limit:          20,
			offset:         0,
			total:          0,
			expectedPage:   1,
			expectedTotal:  0,
			expectedHasNext: false,
			expectedHasPrev: false,
		},
		{
			name:           "Single page",
			limit:          20,
			offset:         0,
			total:          15,
			expectedPage:   1,
			expectedTotal:  15,
			expectedHasNext: false,
			expectedHasPrev: false,
		},
		{
			name:           "Exact page boundary",
			limit:          20,
			offset:         40,
			total:          60,
			expectedPage:   3,
			expectedTotal:  60,
			expectedHasNext: false,
			expectedHasPrev: true,
		},
		{
			name:           "Offset not multiple of limit",
			limit:          20,
			offset:         30,
			total:          100,
			expectedPage:   2, // (30/20) + 1 = 2
			expectedTotal:  100,
			expectedHasNext: true,
			expectedHasPrev: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := helpers.BuildPaginationInfo(tt.limit, tt.offset, tt.total)

			assert.Equal(t, tt.expectedPage, info.Page)
			assert.Equal(t, tt.limit, info.PageSize)
			assert.Equal(t, tt.expectedTotal, info.Total)
			assert.Equal(t, tt.expectedHasNext, info.HasNext)
			assert.Equal(t, tt.expectedHasPrev, info.HasPrev)
			
			// Verify total pages calculation
			expectedTotalPages := int((tt.total + int64(tt.limit) - 1) / int64(tt.limit))
			if expectedTotalPages == 0 {
				expectedTotalPages = 1
			}
			assert.Equal(t, expectedTotalPages, info.TotalPages)
		})
	}
}

func TestValidatePaginationParams(t *testing.T) {
	tests := []struct {
		name     string
		limit    int
		offset   int
		expected error
	}{
		{"Valid params", 20, 0, nil},
		{"Valid with offset", 20, 100, nil},
		{"Limit too low", 0, 0, assert.AnError},
		{"Limit too high", 101, 0, assert.AnError},
		{"Negative offset", 20, -1, assert.AnError},
		{"Exact min limit", 1, 0, nil},
		{"Exact max limit", 100, 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidatePaginationParams(tt.limit, tt.offset)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateSortField(t *testing.T) {
	allowedFields := []string{"id", "name", "created_at", "updated_at"}

	tests := []struct {
		name     string
		sortField string
		expected error
	}{
		{"Valid field", "id", nil},
		{"Valid another field", "name", nil},
		{"Empty field", "", nil},
		{"Invalid field", "invalid_field", assert.AnError},
		{"Case sensitive", "ID", assert.AnError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateSortField(tt.sortField, allowedFields)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestCalculateDBOffset(t *testing.T) {
	tests := []struct {
		name   string
		offset int
	}{
		{"Zero offset", 0},
		{"Positive offset", 100},
		{"Large offset", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := helpers.CalculateDBOffset(tt.offset)
			assert.Equal(t, tt.offset, result)
		})
	}
}

func TestGetPaginationSQL(t *testing.T) {
	tests := []struct {
		name     string
		limit    int
		offset   int
		expected string
		hasError bool
	}{
		{"Valid params", 20, 0, "LIMIT 20 OFFSET 0", false},
		{"Valid with offset", 20, 100, "LIMIT 20 OFFSET 100", false},
		{"Invalid limit", 0, 0, "", true},
		{"Invalid offset", 20, -1, "", true},
		{"Single record", 1, 0, "LIMIT 1 OFFSET 0", false},
		{"Maximum limit", 100, 0, "LIMIT 100 OFFSET 0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sql, err := helpers.GetPaginationSQL(tt.limit, tt.offset)
			
			if tt.hasError {
				assert.Error(t, err)
				assert.Empty(t, sql)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, sql)
			}
		})
	}
}

