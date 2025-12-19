package dto

import (
	"reflect"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/dto"
)

func TestNewStandardListResponse(t *testing.T) {
	items := []string{"a", "b", "c"}
	resp := dto.NewStandardListResponse(items, len(items))

	// Usa reflect.DeepEqual invece di != per confrontare slice
	if !reflect.DeepEqual(resp.Items, items) {
		t.Errorf("expected items %v, got %v", items, resp.Items)
	}

	if resp.Count != 3 {
		t.Errorf("expected count 3, got %d", resp.Count)
	}
}

func TestNewStandardListResponseWithTotal(t *testing.T) {
	items := []int{10, 20}
	resp := dto.NewStandardListResponseWithTotal(items, 2, 100)

	// Usa reflect.DeepEqual invece di !=
	if !reflect.DeepEqual(resp.Items, items) {
		t.Errorf("expected items %v, got %v", items, resp.Items)
	}

	if resp.Count != 2 {
		t.Errorf("expected count 2, got %d", resp.Count)
	}

	if resp.Total != 100 {
		t.Errorf("expected total 100, got %d", resp.Total)
	}
}

func TestFromUserModel(t *testing.T) {
	now := time.Now()
	user := &models.User{
		ID:           1,
		Email:        "test@example.com",
		Name:         "Test",
		Role:         "admin",
		Active:       true,
		TwoFAEnabled: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	resp := dto.FromUserModel(user)

	if resp.ID != user.ID ||
		resp.Email != user.Email ||
		resp.Name != user.Name ||
		resp.Role != user.Role ||
		resp.Active != user.Active ||
		resp.TwoFAEnabled != user.TwoFAEnabled {
		t.Errorf("user model conversion mismatch")
	}

	if resp.CreatedAt != now || resp.UpdatedAt != now {
		t.Errorf("timestamp mismatch")
	}
}

func TestFromUserModelNil(t *testing.T) {
	resp := dto.FromUserModel(nil)
	if resp != nil {
		t.Errorf("expected nil response for nil model")
	}
}

func TestFromRuleModel(t *testing.T) {
	now := time.Now()
	rule := &models.Rule{
		ID:               10,
		Name:             "SQL Injection",
		Type:             "sqli",
		Pattern:          ".*union.*",
		Description:      "Detect SQLi",
		Action:           "block",
		Enabled:          true,
		BlockEnabled:     true,
		DropEnabled:      false,
		RedirectEnabled:  false,
		ChallengeEnabled: false,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	resp := dto.FromRuleModel(rule)

	if resp.ID != rule.ID ||
		resp.Name != rule.Name ||
		resp.Type != rule.Type ||
		resp.Pattern != rule.Pattern ||
		resp.Description != rule.Description ||
		resp.Action != rule.Action ||
		resp.Enabled != rule.Enabled {
		t.Errorf("rule model conversion mismatch")
	}

	if resp.CreatedAt != now || resp.UpdatedAt != now {
		t.Errorf("timestamp mismatch")
	}
}

func TestFromRuleModelNil(t *testing.T) {
	resp := dto.FromRuleModel(nil)
	if resp != nil {
		t.Errorf("expected nil response for nil model")
	}
}

func TestFromLogModel(t *testing.T) {
	now := time.Now()
	log := &models.Log{
		ID:          99,
		ClientIP:    "1.2.3.4",
		ThreatType:  "xss",
		Description: "Attempted XSS attack",
		Method:      "GET",
		URL:         "/test",
		Payload:     "<script>",
		UserAgent:   "Mozilla",
		Blocked:     true,
		BlockedBy:   "rule-10",
		Severity:    "high",
		CreatedAt:   now,
	}

	resp := dto.FromLogModel(log)

	if resp.ID != log.ID ||
		resp.ClientIP != log.ClientIP ||
		resp.ThreatType != log.ThreatType ||
		resp.Description != log.Description ||
		resp.Method != log.Method ||
		resp.URL != log.URL ||
		resp.Payload != log.Payload ||
		resp.UserAgent != log.UserAgent ||
		resp.Blocked != log.Blocked ||
		resp.BlockedBy != log.BlockedBy ||
		resp.Severity != log.Severity {
		t.Errorf("log model conversion mismatch")
	}

	if resp.CreatedAt != now {
		t.Errorf("timestamp mismatch")
	}
}

func TestFromLogModelNil(t *testing.T) {
	resp := dto.FromLogModel(nil)
	if resp != nil {
		t.Errorf("expected nil response for nil model")
	}
}

func TestPaginationInfo(t *testing.T) {
	p := dto.PaginationInfo{
		Page:       1,
		PageSize:   20,
		Total:      100,
		TotalPages: 5,
		HasNext:    true,
		HasPrev:    false,
	}

	if p.Page != 1 || p.PageSize != 20 || p.Total != 100 || p.TotalPages != 5 {
		t.Errorf("pagination fields mismatch")
	}

	if !p.HasNext || p.HasPrev {
		t.Errorf("pagination next/prev mismatch")
	}
}

func TestPaginatedResponse(t *testing.T) {
	data := []string{"a", "b"}
	pagination := dto.PaginationInfo{Page: 1, PageSize: 2}

	resp := dto.PaginatedResponse{
		Data:       data,
		Pagination: pagination,
	}

	// Usa reflect.DeepEqual invece di !=
	if !reflect.DeepEqual(resp.Data, data) {
		t.Errorf("expected data %v, got %v", data, resp.Data)
	}

	if resp.Pagination != pagination {
		t.Errorf("pagination mismatch")
	}
}

func TestStandardPaginatedResponse(t *testing.T) {
	items := []int{1, 2, 3}
	pagination := dto.PaginationInfo{Page: 1, PageSize: 3}

	resp := dto.StandardPaginatedResponse{
		Items:      items,
		Pagination: pagination,
	}

	// Usa reflect.DeepEqual invece di !=
	if !reflect.DeepEqual(resp.Items, items) {
		t.Errorf("expected items %v, got %v", items, resp.Items)
	}

	if resp.Pagination != pagination {
		t.Errorf("pagination mismatch")
	}
}

func TestResponseEnvelope(t *testing.T) {
	now := time.Now()

	env := dto.ResponseEnvelope{
		Success:   true,
		Message:   "OK",
		Data:      "payload",
		Error:     "",
		Timestamp: now,
	}

	if !env.Success || env.Message != "OK" || env.Data != "payload" || env.Error != "" {
		t.Errorf("response envelope mismatch")
	}

	if env.Timestamp != now {
		t.Errorf("timestamp mismatch")
	}
}