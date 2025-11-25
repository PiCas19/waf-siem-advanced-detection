package helpers

// Allowed sort fields for different resources
// These can be used with ValidateSortField() to ensure only valid columns are used

var (
	// BlocklistSortFields are valid sort fields for blocklist queries
	BlocklistSortFields = []string{
		"id",
		"ip_address",
		"created_at",
		"expires_at",
	}

	// WhitelistSortFields are valid sort fields for whitelist queries
	WhitelistSortFields = []string{
		"id",
		"ip_address",
		"created_at",
	}

	// RulesSortFields are valid sort fields for rules queries
	RulesSortFields = []string{
		"id",
		"name",
		"type",
		"created_at",
		"updated_at",
		"enabled",
	}

	// LogsSortFields are valid sort fields for logs queries
	LogsSortFields = []string{
		"id",
		"client_ip",
		"threat_type",
		"severity",
		"created_at",
		"blocked",
	}

	// AuditLogsSortFields are valid sort fields for audit logs queries
	AuditLogsSortFields = []string{
		"id",
		"user_id",
		"action",
		"category",
		"created_at",
		"status",
	}

	// FalsePositivesSortFields are valid sort fields for false positives queries
	FalsePositivesSortFields = []string{
		"id",
		"threat_type",
		"status",
		"created_at",
		"reviewed_at",
	}

	// UsersSortFields are valid sort fields for users queries
	UsersSortFields = []string{
		"id",
		"email",
		"name",
		"role",
		"created_at",
		"active",
	}
)
