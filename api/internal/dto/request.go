package dto

// Blocklist DTOs

// BlockIPRequest represents a request to block an IP address.
//
// Fields:
//   - IP (string): IP address to block (required)
//   - Threat (string): Type of threat detected (required)
//   - Reason (string): Explanation for blocking (required)
//   - Permanent (bool): Whether this is a permanent block
//   - DurationHours (int): Duration in hours for temporary blocks
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type BlockIPRequest struct {
	IP            string `json:"ip" binding:"required"`
	Threat        string `json:"threat" binding:"required"`
	Reason        string `json:"reason" binding:"required"`
	Permanent     bool   `json:"permanent"`
	DurationHours int    `json:"duration_hours"`
}

// UnblockIPRequest represents a request to unblock an IP address.
//
// Fields:
//   - IP (string): IP address to unblock (required)
//   - Threat (string): Type of threat to remove block for (required)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type UnblockIPRequest struct {
	IP     string `json:"ip" binding:"required"`
	Threat string `json:"threat" binding:"required"`
}

// Whitelist DTOs

// AddToWhitelistRequest represents a request to add an IP to the whitelist.
//
// Fields:
//   - IPAddress (string): IP address to whitelist (required)
//   - Reason (string): Explanation for whitelisting (required)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type AddToWhitelistRequest struct {
	IPAddress string `json:"ip_address" binding:"required"`
	Reason    string `json:"reason" binding:"required"`
}

// RemoveFromWhitelistRequest represents a request to remove an IP from the whitelist.
//
// Fields:
//   - ID (string): ID of the whitelisted entry to remove (required, from URI)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type RemoveFromWhitelistRequest struct {
	ID string `uri:"id" binding:"required"`
}

// Rule DTOs

// CreateRuleRequest represents a request to create a new WAF detection rule.
//
// Fields:
//   - Name (string): Name of the rule (required)
//   - Type (string): Threat type - xss, sqli, lfi, rfi, cmd (required)
//   - Pattern (string): Regex pattern to match (required)
//   - Description (string): Detailed description
//   - Action (string): Action to take - log or block (required)
//   - Enabled (bool): Whether rule is active
//   - BlockEnabled (bool): Reject request immediately
//   - DropEnabled (bool): Terminate connection without response
//   - RedirectEnabled (bool): Redirect to security page
//   - ChallengeEnabled (bool): Require CAPTCHA verification
//
// Thread Safety: Immutable after creation, safe for concurrent use.
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

// UpdateRuleRequest represents a request to update an existing WAF rule.
// All fields except ID are optional.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
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

// ReportFalsePositiveRequest represents a request to report a false positive detection.
//
// Fields:
//   - ThreatType (string): Type of threat incorrectly detected (required)
//   - Description (string): Description from the rule that triggered
//   - ClientIP (string): IP that triggered the false positive (required)
//   - Method (string): HTTP method
//   - URL (string): URL that triggered it
//   - Payload (string): Detected payload
//   - UserAgent (string): User agent string
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type ReportFalsePositiveRequest struct{
	ThreatType  string `json:"threat_type" binding:"required"`
	Description string `json:"description"`
	ClientIP    string `json:"client_ip" binding:"required"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Payload     string `json:"payload"`
	UserAgent   string `json:"user_agent"`
}

// UpdateFalsePositiveStatusRequest represents a request to update false positive review status.
//
// Fields:
//   - Status (string): New status - pending, reviewed, or whitelisted (required)
//   - ReviewNotes (string): Review notes
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type UpdateFalsePositiveStatusRequest struct {
	Status      string `json:"status" binding:"required"`
	ReviewNotes string `json:"review_notes"`
}

// User DTOs

// UpdateUserRequest represents a request to update user information.
// All fields except ID are optional.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type UpdateUserRequest struct{
	ID     uint   `uri:"id" binding:"required"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Active *bool  `json:"active"`
}

// DeleteUserRequest represents a request to delete a user.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type DeleteUserRequest struct {
	ID uint `uri:"id" binding:"required"`
}

// Pagination DTOs

// PaginationRequest represents pagination parameters for list queries.
//
// Fields:
//   - Page (int): Page number (min: 1, default: 1)
//   - PageSize (int): Items per page (min: 1, max: 500, default: 50)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type PaginationRequest struct {
	Page     int `query:"page,default=1" binding:"min=1"`
	PageSize int `query:"limit,default=50" binding:"min=1,max=500"`
}

// Auth DTOs

// LoginRequest represents a user login request (password authentication).
//
// Fields:
//   - Email (string): User email (required, must be valid email)
//   - Password (string): User password (required, min 6 characters)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// VerifyOTPRequest represents a 2FA OTP verification request.
//
// Fields:
//   - Email (string): User email (required)
//   - OTP (string): 6-digit OTP code (required, exactly 6 characters)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type VerifyOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
	OTP   string `json:"otp" binding:"required,len=6"`
}

// SetPasswordRequest represents a password set request using reset token.
//
// Fields:
//   - Token (string): Password reset/invite token (required)
//   - Password (string): New password (required, min 8 characters)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type SetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

// ForgotPasswordRequest represents a password reset initiation request.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents a password reset confirmation request.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type ResetPasswordRequest struct{
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

// ChangePasswordRequest represents an authenticated password change request.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// InitiateTwoFARequest represents a 2FA setup initiation request.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type InitiateTwoFARequest struct {
	Method string `json:"method" binding:"required,oneof=totp email"`
}

// CompleteTwoFARequest represents a 2FA setup completion request.
//
// Fields:
//   - Secret (string): TOTP secret from initiation (required)
//   - Code (string): 6-digit verification code (required)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type CompleteTwoFARequest struct {
	Secret string `json:"secret" binding:"required"`
	Code   string `json:"code" binding:"required,len=6"`
}

// VerifyTwoFARequest represents a 2FA code verification during login.
//
// Thread Safety: Immutable after creation, safe for concurrent use.
type VerifyTwoFARequest struct {
	Code string `json:"code" binding:"required,len=6"`
}
