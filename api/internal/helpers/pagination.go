package helpers

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/dto"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/validators"
)

// DefaultPageSize is the default number of items per page
const DefaultPageSize = 20

// MaxPageSize is the maximum allowed page size
const MaxPageSize = 100

// MinPageSize is the minimum allowed page size
const MinPageSize = 1

// ParsePaginationParams parses pagination parameters from query string
// Returns limit, offset, sort field, sort order, and error
// Defaults: limit=20, offset=0, sort="" (no sorting), order="asc"
func ParsePaginationParams(c *gin.Context) (limit, offset int, sort, order string, err error) {
	// Parse limit
	limitStr := c.DefaultQuery("limit", fmt.Sprintf("%d", DefaultPageSize))
	limit, err = strconv.Atoi(limitStr)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("invalid limit: %w", err)
	}

	// Validate limit
	if limit < MinPageSize {
		limit = MinPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}

	// Parse offset
	offsetStr := c.DefaultQuery("offset", "0")
	offset, err = strconv.Atoi(offsetStr)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("invalid offset: %w", err)
	}

	// Validate offset
	if offset < 0 {
		offset = 0
	}

	// Parse sort field (optional)
	sort = c.Query("sort")

	// Parse sort order (optional)
	order = c.DefaultQuery("order", "asc")
	if order != "asc" && order != "desc" {
		order = "asc"
	}

	return limit, offset, sort, order, nil
}

// ParsePaginationParamsWithDefaults parses pagination with custom defaults
func ParsePaginationParamsWithDefaults(c *gin.Context, defaultLimit int) (limit, offset int, sort, order string, err error) {
	// Validate default limit
	if defaultLimit < MinPageSize {
		defaultLimit = MinPageSize
	}
	if defaultLimit > MaxPageSize {
		defaultLimit = MaxPageSize
	}

	limitStr := c.DefaultQuery("limit", fmt.Sprintf("%d", defaultLimit))
	limit, err = strconv.Atoi(limitStr)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("invalid limit: %w", err)
	}

	if limit < MinPageSize {
		limit = MinPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}

	offsetStr := c.DefaultQuery("offset", "0")
	offset, err = strconv.Atoi(offsetStr)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("invalid offset: %w", err)
	}

	if offset < 0 {
		offset = 0
	}

	sort = c.Query("sort")
	order = c.DefaultQuery("order", "asc")
	if order != "asc" && order != "desc" {
		order = "asc"
	}

	return limit, offset, sort, order, nil
}

// BuildPaginationInfo builds pagination info from counts and parameters
func BuildPaginationInfo(limit, offset int, total int64) dto.PaginationInfo {
	// Calculate page number (0-based index: offset 0 = page 1, offset 20 = page 2)
	page := (offset / limit) + 1

	// Calculate total pages
	totalPages := int((total + int64(limit) - 1) / int64(limit))
	if totalPages == 0 {
		totalPages = 1
	}

	// Check if there are next/previous pages
	hasNext := (offset + limit) < int(total)
	hasPrev := offset > 0

	return dto.PaginationInfo{
		Page:       page,
		PageSize:   limit,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    hasNext,
		HasPrev:    hasPrev,
	}
}

// BuildStandardPaginatedResponse creates a paginated response with items
func BuildStandardPaginatedResponse(items interface{}, limit, offset int, total int64) dto.StandardPaginatedResponse {
	pagination := BuildPaginationInfo(limit, offset, total)
	return dto.StandardPaginatedResponse{
		Items:      items,
		Pagination: pagination,
	}
}

// ValidatePaginationParams validates pagination parameters
func ValidatePaginationParams(limit, offset int) error {
	if limit < MinPageSize {
		return fmt.Errorf("limit must be at least %d", MinPageSize)
	}
	if limit > MaxPageSize {
		return fmt.Errorf("limit cannot exceed %d", MaxPageSize)
	}
	if offset < 0 {
		return fmt.Errorf("offset cannot be negative")
	}
	return nil
}

// ValidateSortField validates that sort field is in allowed fields
// Empty string is always valid (no sorting)
func ValidateSortField(sortField string, allowedFields []string) error {
	if sortField == "" {
		return nil // Empty sort field is valid
	}

	if !validators.IsValidChoice(sortField, allowedFields) {
		return fmt.Errorf("invalid sort field: %s. allowed fields: %v", sortField, allowedFields)
	}
	return nil
}

// CalculateDBOffset converts API offset to database offset for pagination
// API offset is absolute (e.g., 0, 20, 40...)
// DB offset can be used with LIMIT/OFFSET directly
func CalculateDBOffset(offset int) int {
	return offset
}

// GetPaginationSQL returns LIMIT and OFFSET SQL clauses
func GetPaginationSQL(limit, offset int) (string, error) {
	if err := ValidatePaginationParams(limit, offset); err != nil {
		return "", err
	}

	return fmt.Sprintf("LIMIT %d OFFSET %d", limit, offset), nil
}
