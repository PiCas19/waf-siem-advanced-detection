package dto

import (
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// Generic Response Envelope

// ResponseEnvelope is a standardized response wrapper for all API responses.
//
// Fields:
//   - Success (bool): Whether the operation succeeded
//   - Message (string): Human-readable message
//   - Data (interface{}): Response payload
//   - Error (string): Error message if operation failed
//   - Timestamp (time.Time): Response timestamp
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type ResponseEnvelope struct{
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// StandardListResponse is the standard format for all list responses.
// Replaces: blocked_ips, whitelisted_ips, rules, users, etc.
//
// Fields:
//   - Items (interface{}): Slice of items (BlockedIP, User, Rule, etc.)
//   - Count (int): Number of items returned
//   - Total (int64): Total count for pagination (optional)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type StandardListResponse struct {
	Items interface{} `json:"items"`       // Slice di items (BlockedIP, User, Rule, etc.)
	Count int         `json:"count"`       // Numero di items
	Total int64       `json:"total,omitempty"` // Total count (per pagination)
}

// NewStandardListResponse crea una risposta di lista standardizzata
func NewStandardListResponse(items interface{}, count int) StandardListResponse {
	return StandardListResponse{
		Items: items,
		Count: count,
	}
}

// NewStandardListResponseWithTotal crea una risposta di lista con total (per pagination)
func NewStandardListResponseWithTotal(items interface{}, count int, total int64) StandardListResponse {
	return StandardListResponse{
		Items: items,
		Count: count,
		Total: total,
	}
}

// PaginationParams holds pagination query parameters.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type PaginationParams struct {
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	Sort   string `json:"sort"`
	Order  string `json:"order"` // asc or desc
}

// PaginatedResponse wraps data with pagination metadata.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type PaginatedResponse struct {
	Data       interface{}     `json:"data"`
	Pagination PaginationInfo `json:"pagination"`
}

// PaginationInfo contains metadata about paginated results.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type PaginationInfo struct{
	Page       int   `json:"page"`
	PageSize   int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// StandardPaginatedResponse combines items with pagination metadata.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type StandardPaginatedResponse struct{
	Items      interface{}  `json:"items"`
	Pagination PaginationInfo `json:"pagination"`
}

// Rule Response DTOs

type RuleResponse struct {
	ID                uint      `json:"id"`
	Name              string    `json:"name"`
	Type              string    `json:"type"`
	Pattern           string    `json:"pattern"`
	Description       string    `json:"description"`
	Action            string    `json:"action"`
	Enabled           bool      `json:"enabled"`
	BlockEnabled      bool      `json:"block_enabled"`
	DropEnabled       bool      `json:"drop_enabled"`
	RedirectEnabled   bool      `json:"redirect_enabled"`
	ChallengeEnabled  bool      `json:"challenge_enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RulesListResponse struct {
	DefaultRules []DefaultRuleResponse `json:"default_rules"`
	CustomRules  []RuleResponse        `json:"custom_rules"`
	TotalRules   int                   `json:"total_rules"`
}

type DefaultRuleResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// User Response DTOs

type UserResponse struct {
	ID            uint      `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Role          string    `json:"role"`
	Active        bool      `json:"active"`
	TwoFAEnabled  bool      `json:"two_fa_enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type UsersListResponse struct {
	Users []UserResponse `json:"users"`
	Count int            `json:"count"`
}

// IP Response DTOs

type BlockedIPResponse struct {
	ID          uint       `json:"id"`
	IPAddress   string     `json:"ip_address"`
	Description string     `json:"description"`
	Reason      string     `json:"reason"`
	Permanent   bool       `json:"permanent"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type BlocklistResponse struct {
	BlockedIPs []BlockedIPResponse `json:"blocked_ips"`
	Count      int                 `json:"count"`
}

type WhitelistedIPResponse struct {
	ID        uint      `json:"id"`
	IPAddress string    `json:"ip_address"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type WhitelistResponse struct {
	WhitelistedIPs []WhitelistedIPResponse `json:"whitelisted_ips"`
	Count          int                     `json:"count"`
}

// Log Response DTOs

type LogResponse struct {
	ID          uint      `json:"id"`
	ClientIP    string    `json:"client_ip"`
	ThreatType  string    `json:"threat_type"`
	Description string    `json:"description"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Payload     string    `json:"payload"`
	UserAgent   string    `json:"user_agent"`
	Blocked     bool      `json:"blocked"`
	BlockedBy   string    `json:"blocked_by"`
	Severity    string    `json:"severity"`
	CreatedAt   time.Time `json:"created_at"`
}

type LogsResponse struct {
	SecurityLogs []LogResponse `json:"security_logs"`
	AuditLogs    []AuditLogResponse `json:"audit_logs"`
	Count        int           `json:"count"`
}

// Audit Log Response DTOs

type AuditLogResponse struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	Email     string    `json:"email"`
	Action    string    `json:"action"`
	Category  string    `json:"category"`
	Subject   string    `json:"subject"`
	Value     string    `json:"value"`
	Details   string    `json:"details"`
	Status    string    `json:"status"`
	ClientIP  string    `json:"client_ip"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditLogsResponse struct {
	AuditLogs []AuditLogResponse `json:"audit_logs"`
	Count     int                `json:"count"`
}

type AuditLogStatsResponse struct {
	TotalActions      int64                 `json:"total_actions"`
	SuccessfulActions int64                 `json:"successful_actions"`
	FailedActions     int64                 `json:"failed_actions"`
	ActionBreakdown   map[string]int64 `json:"action_breakdown"`
}

// False Positive Response DTOs

type FalsePositiveResponse struct {
	ID          uint       `json:"id"`
	ThreatType  string     `json:"threat_type"`
	Description string     `json:"description"`
	ClientIP    string     `json:"client_ip"`
	Method      string     `json:"method"`
	URL         string     `json:"url"`
	Payload     string     `json:"payload"`
	UserAgent   string     `json:"user_agent"`
	Status      string     `json:"status"`
	ReviewNotes string     `json:"review_notes"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type FalsePositivesResponse struct {
	FalsePositives []FalsePositiveResponse `json:"false_positives"`
	Count          int                     `json:"count"`
}

// Threat Intelligence Response DTOs

type ThreatIntelResponse struct {
	IP           string                 `json:"ip"`
	MaliciousBy  []string               `json:"malicious_by"`
	ThreatLevel  string                 `json:"threat_level"`
	LastAnalyzed time.Time              `json:"last_analyzed"`
	Details      map[string]interface{} `json:"details"`
}

// Stats Response DTOs

type WafStatsResponse struct {
	TotalRequests      int64                  `json:"total_requests"`
	BlockedRequests    int64                  `json:"blocked_requests"`
	BlockRate          float64                `json:"block_rate"`
	ThreatBreakdown    map[string]int64  `json:"threat_breakdown"`
	TopBlockedIPs      []IPStatsResponse      `json:"top_blocked_ips"`
	RecentThreats      []LogResponse          `json:"recent_threats"`
	AverageResponseTime float64                `json:"average_response_time_ms"`
}

type IPStatsResponse struct {
	IP              string `json:"ip"`
	BlockCount      int64  `json:"block_count"`
	ThreatType      string `json:"threat_type"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	IsBlacklisted   bool   `json:"is_blacklisted"`
	Reputation      string `json:"reputation,omitempty"`
	ThreatLevel     string `json:"threat_level,omitempty"`
}

// Auth Response DTOs

type LoginResponse struct {
	Token       string                 `json:"token"`
	ExpiresAt   time.Time              `json:"expires_at"`
	User        UserResponse           `json:"user"`
	TwoFANeeded bool                   `json:"two_fa_needed"`
}

type OTPResponse struct {
	Message string `json:"message"`
	Method  string `json:"method"`
}

type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TwoFASetupResponse struct {
	Secret  string `json:"secret"`
	QRCode  string `json:"qr_code"`
	Message string `json:"message"`
}

// Helper function to convert models to DTOs

func FromUserModel(user *models.User) *UserResponse {
	if user == nil {
		return nil
	}
	return &UserResponse{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		Role:         user.Role,
		Active:       user.Active,
		TwoFAEnabled: user.TwoFAEnabled,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

func FromRuleModel(rule *models.Rule) *RuleResponse {
	if rule == nil {
		return nil
	}
	return &RuleResponse{
		ID:               rule.ID,
		Name:             rule.Name,
		Type:             rule.Type,
		Pattern:          rule.Pattern,
		Description:      rule.Description,
		Action:           rule.Action,
		Enabled:          rule.Enabled,
		BlockEnabled:     rule.BlockEnabled,
		DropEnabled:      rule.DropEnabled,
		RedirectEnabled:  rule.RedirectEnabled,
		ChallengeEnabled: rule.ChallengeEnabled,
		CreatedAt:        rule.CreatedAt,
		UpdatedAt:        rule.UpdatedAt,
	}
}

func FromLogModel(log *models.Log) *LogResponse {
	if log == nil {
		return nil
	}
	return &LogResponse{
		ID:          log.ID,
		ClientIP:    log.ClientIP,
		ThreatType:  log.ThreatType,
		Description: log.Description,
		Method:      log.Method,
		URL:         log.URL,
		Payload:     log.Payload,
		UserAgent:   log.UserAgent,
		Blocked:     log.Blocked,
		BlockedBy:   log.BlockedBy,
		Severity:    log.Severity,
		CreatedAt:   log.CreatedAt,
	}
}
