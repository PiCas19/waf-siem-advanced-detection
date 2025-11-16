package dto

// Blocklist DTOs

type BlockIPRequest struct {
	IP            string `json:"ip" binding:"required"`
	Threat        string `json:"threat" binding:"required"`
	Reason        string `json:"reason" binding:"required"`
	Permanent     bool   `json:"permanent"`
	DurationHours int    `json:"duration_hours"`
}

type UnblockIPRequest struct {
	IP     string `json:"ip" binding:"required"`
	Threat string `json:"threat" binding:"required"`
}

// Whitelist DTOs

type AddToWhitelistRequest struct {
	IPAddress string `json:"ip_address" binding:"required"`
	Reason    string `json:"reason" binding:"required"`
}

type RemoveFromWhitelistRequest struct {
	ID string `uri:"id" binding:"required"`
}

// Rule DTOs

type CreateRuleRequest struct {
	Name              string `json:"name" binding:"required"`
	Type              string `json:"type" binding:"required"`
	Pattern           string `json:"pattern" binding:"required"`
	Description       string `json:"description"`
	Action            string `json:"action" binding:"required"`
	Enabled           bool   `json:"enabled"`
	BlockEnabled      bool   `json:"block_enabled"`
	DropEnabled       bool   `json:"drop_enabled"`
	RedirectEnabled   bool   `json:"redirect_enabled"`
	ChallengeEnabled  bool   `json:"challenge_enabled"`
}

type UpdateRuleRequest struct {
	ID                uint   `uri:"id" binding:"required"`
	Name              string `json:"name"`
	Pattern           string `json:"pattern"`
	Description       string `json:"description"`
	Action            string `json:"action"`
	Enabled           bool   `json:"enabled"`
	BlockEnabled      bool   `json:"block_enabled"`
	DropEnabled       bool   `json:"drop_enabled"`
	RedirectEnabled   bool   `json:"redirect_enabled"`
	ChallengeEnabled  bool   `json:"challenge_enabled"`
}

// False Positive DTOs

type ReportFalsePositiveRequest struct {
	ThreatType  string `json:"threat_type" binding:"required"`
	Description string `json:"description"`
	ClientIP    string `json:"client_ip" binding:"required"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Payload     string `json:"payload"`
	UserAgent   string `json:"user_agent"`
}

type UpdateFalsePositiveStatusRequest struct {
	Status      string `json:"status" binding:"required"`
	ReviewNotes string `json:"review_notes"`
}

// User DTOs

type UpdateUserRequest struct {
	ID     uint   `uri:"id" binding:"required"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Active *bool  `json:"active"`
}

type DeleteUserRequest struct {
	ID uint `uri:"id" binding:"required"`
}

// Pagination DTOs

type PaginationRequest struct {
	Page     int `query:"page,default=1" binding:"min=1"`
	PageSize int `query:"limit,default=50" binding:"min=1,max=500"`
}

// Auth DTOs

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type VerifyOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
	OTP   string `json:"otp" binding:"required,len=6"`
}

type SetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type InitiateTwoFARequest struct {
	Method string `json:"method" binding:"required,oneof=totp email"`
}

type CompleteTwoFARequest struct {
	Secret string `json:"secret" binding:"required"`
	Code   string `json:"code" binding:"required,len=6"`
}

type VerifyTwoFARequest struct {
	Code string `json:"code" binding:"required,len=6"`
}
