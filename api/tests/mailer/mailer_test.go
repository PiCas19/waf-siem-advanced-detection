package mailer

import (
	"os"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/mailer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Initialize logger for tests
	logger.InitLogger("error", "/dev/null")
}

// TestNewMailerFromEnv_Success tests successful mailer creation from env vars
func TestNewMailerFromEnv_Success(t *testing.T) {
	// Set environment variables
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_USER", "user@example.com")
	os.Setenv("SMTP_PASS", "password")
	os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
	os.Setenv("NO_REPLY_NAME", "WAF Dashboard")
	os.Setenv("SUPPORT_EMAIL", "support@example.com")
	os.Setenv("SITE_URL", "https://dashboard.example.com")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	require.NotNil(t, m)
	assert.Equal(t, "smtp.example.com", m.Host)
	assert.Equal(t, 587, m.Port)
	assert.Equal(t, "user@example.com", m.Username)
	assert.Equal(t, "password", m.Password)
	assert.Equal(t, "noreply@example.com", m.FromEmail)
	assert.Equal(t, "WAF Dashboard", m.FromName)
	assert.Equal(t, "support@example.com", m.ReplyTo)
	assert.Equal(t, "https://dashboard.example.com", m.SiteURL)
}

// TestNewMailerFromEnv_MissingHost tests with missing SMTP_HOST
func TestNewMailerFromEnv_MissingHost(t *testing.T) {
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	assert.Nil(t, m)
}

// TestNewMailerFromEnv_MissingPort tests with missing SMTP_PORT
func TestNewMailerFromEnv_MissingPort(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	assert.Nil(t, m)
}

// TestNewMailerFromEnv_MissingFromEmail tests with missing NO_REPLY_EMAIL
func TestNewMailerFromEnv_MissingFromEmail(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_PORT", "587")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	assert.Nil(t, m)
}

// TestNewMailerFromEnv_InvalidPort tests with invalid port
func TestNewMailerFromEnv_InvalidPort(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_PORT", "invalid")
	os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	require.NotNil(t, m)
	assert.Equal(t, 587, m.Port) // Should default to 587
}

// TestNewMailerFromEnv_MinimalConfig tests with minimal configuration
func TestNewMailerFromEnv_MinimalConfig(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_PORT", "25")
	os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	require.NotNil(t, m)
	assert.Equal(t, "smtp.example.com", m.Host)
	assert.Equal(t, 25, m.Port)
	assert.Equal(t, "noreply@example.com", m.FromEmail)
	assert.Empty(t, m.FromName)
	assert.Empty(t, m.ReplyTo)
	assert.Empty(t, m.SiteURL)
}

// TestNewMailerFromEnv_WithWhitespace tests trimming whitespace
func TestNewMailerFromEnv_WithWhitespace(t *testing.T) {
	os.Setenv("SMTP_HOST", "  smtp.example.com  ")
	os.Setenv("SMTP_PORT", "  587  ")
	os.Setenv("NO_REPLY_EMAIL", "  noreply@example.com  ")
	os.Setenv("NO_REPLY_NAME", "  WAF Dashboard  ")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	require.NotNil(t, m)
	assert.Equal(t, "smtp.example.com", m.Host)
	assert.Equal(t, "noreply@example.com", m.FromEmail)
	assert.Equal(t, "WAF Dashboard", m.FromName)
}

// TestNewMailerFromEnv_CustomPort tests custom port
func TestNewMailerFromEnv_CustomPort(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_PORT", "465")
	os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	require.NotNil(t, m)
	assert.Equal(t, 465, m.Port)
}

// TestNewMailerFromEnv_AllOptionalFields tests all optional fields
func TestNewMailerFromEnv_AllOptionalFields(t *testing.T) {
	os.Setenv("SMTP_HOST", "smtp.example.com")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_USER", "user@example.com")
	os.Setenv("SMTP_PASS", "secret")
	os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
	os.Setenv("NO_REPLY_NAME", "My Name")
	os.Setenv("SUPPORT_EMAIL", "support@example.com")
	os.Setenv("SITE_URL", "https://example.com")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	require.NotNil(t, m)
	assert.Equal(t, "user@example.com", m.Username)
	assert.Equal(t, "secret", m.Password)
	assert.Equal(t, "My Name", m.FromName)
	assert.Equal(t, "support@example.com", m.ReplyTo)
	assert.Equal(t, "https://example.com", m.SiteURL)
}

// TestSendEmail_NilMailer tests SendEmail with nil mailer
func TestSendEmail_NilMailer(t *testing.T) {
	var m *mailer.Mailer

	err := m.SendEmail("test@example.com", "Test Subject", "<p>Test Body</p>")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mailer not configured")
}

// TestSendEmail_WithoutSMTPConnection tests SendEmail without SMTP connection
func TestSendEmail_WithoutSMTPConnection(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		Username:  "user",
		Password:  "pass",
		FromEmail: "from@example.com",
	}

	err := m.SendEmail("to@example.com", "Test", "<p>Body</p>")

	// Should fail to connect to invalid SMTP server
	assert.Error(t, err)
}

// TestSendEmail_Structure tests email structure without sending
func TestSendEmail_Structure(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "smtp.example.com",
		Port:      587,
		Username:  "user@example.com",
		Password:  "password",
		FromEmail: "noreply@example.com",
		FromName:  "WAF Dashboard",
		ReplyTo:   "support@example.com",
	}

	// We can't actually send without SMTP, but we verify structure doesn't panic
	assert.NotNil(t, m)
	assert.Equal(t, "smtp.example.com", m.Host)
	assert.Equal(t, 587, m.Port)
}

// TestSendEmail_WithFromName tests SendEmail with FromName set
func TestSendEmail_WithFromName(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		FromEmail: "noreply@example.com",
		FromName:  "WAF Dashboard",
	}

	err := m.SendEmail("to@example.com", "Test", "<p>Body</p>")

	// Will fail but shouldn't panic
	assert.Error(t, err)
}

// TestSendEmail_WithReplyTo tests SendEmail with ReplyTo set
func TestSendEmail_WithReplyTo(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		FromEmail: "noreply@example.com",
		ReplyTo:   "support@example.com",
	}

	err := m.SendEmail("to@example.com", "Test", "<p>Body</p>")

	// Will fail but shouldn't panic
	assert.Error(t, err)
}

// TestSendEmail_EmptyCredentials tests with empty SMTP credentials
func TestSendEmail_EmptyCredentials(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      25,
		Username:  "",
		Password:  "",
		FromEmail: "noreply@example.com",
	}

	err := m.SendEmail("to@example.com", "Test", "<p>Body</p>")

	// Will fail but shouldn't panic with empty credentials
	assert.Error(t, err)
}

// TestSendInvite_NilMailer tests SendInvite with nil mailer
func TestSendInvite_NilMailer(t *testing.T) {
	var m *mailer.Mailer

	err := m.SendInvite("test@example.com", "John Doe", "/reset?token=abc", "temp123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mailer not configured")
}

// TestSendInvite_WithoutSMTPConnection tests SendInvite without SMTP connection
func TestSendInvite_WithoutSMTPConnection(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		Username:  "user",
		Password:  "pass",
		FromEmail: "from@example.com",
		SiteURL:   "https://dashboard.example.com",
	}

	err := m.SendInvite("to@example.com", "John Doe", "/reset?token=abc", "temp123")

	// Should fail to connect
	assert.Error(t, err)
}

// TestSendInvite_LinkFormatting tests link formatting with SiteURL
func TestSendInvite_LinkFormatting(t *testing.T) {
	tests := []struct {
		name      string
		siteURL   string
		resetLink string
		// We can't verify the actual link without sending, but we test structure
	}{
		{"With https link", "https://dashboard.example.com", "/reset?token=abc"},
		{"With trailing slash", "https://dashboard.example.com/", "/reset?token=abc"},
		{"Without leading slash in link", "https://dashboard.example.com", "reset?token=abc"},
		{"Full http link", "https://dashboard.example.com", "http://other.com/reset"},
		{"Empty SiteURL", "", "/reset?token=abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mailer.Mailer{
				Host:      "invalid.smtp.server",
				Port:      587,
				FromEmail: "noreply@example.com",
				SiteURL:   tt.siteURL,
			}

			err := m.SendInvite("to@example.com", "John Doe", tt.resetLink, "temp123")

			// Will fail but shouldn't panic
			assert.Error(t, err)
		})
	}
}

// TestSendInvite_WithFromName tests SendInvite with FromName
func TestSendInvite_WithFromName(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		FromEmail: "noreply@example.com",
		FromName:  "WAF Dashboard",
	}

	err := m.SendInvite("to@example.com", "Jane Doe", "/reset", "temp456")

	// Will fail but shouldn't panic
	assert.Error(t, err)
}

// TestSendInvite_WithReplyTo tests SendInvite with ReplyTo
func TestSendInvite_WithReplyTo(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		FromEmail: "noreply@example.com",
		ReplyTo:   "support@example.com",
	}

	err := m.SendInvite("to@example.com", "Bob Smith", "/reset", "temp789")

	// Will fail but shouldn't panic
	assert.Error(t, err)
}

// TestSendInvite_CompleteStructure tests SendInvite with all fields
func TestSendInvite_CompleteStructure(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		Username:  "user@example.com",
		Password:  "password",
		FromEmail: "noreply@example.com",
		FromName:  "WAF Dashboard",
		ReplyTo:   "support@example.com",
		SiteURL:   "https://dashboard.example.com",
	}

	err := m.SendInvite("newuser@example.com", "New User", "/reset?token=xyz", "tempPass123")

	// Will fail due to invalid SMTP but structure is valid
	assert.Error(t, err)
}

// TestMailerStruct tests Mailer struct creation
func TestMailerStruct(t *testing.T) {
	m := mailer.Mailer{
		Host:      "smtp.gmail.com",
		Port:      587,
		Username:  "test@gmail.com",
		Password:  "password",
		FromEmail: "noreply@test.com",
		FromName:  "Test Sender",
		ReplyTo:   "support@test.com",
		SiteURL:   "https://test.com",
	}

	assert.Equal(t, "smtp.gmail.com", m.Host)
	assert.Equal(t, 587, m.Port)
	assert.Equal(t, "test@gmail.com", m.Username)
	assert.Equal(t, "password", m.Password)
	assert.Equal(t, "noreply@test.com", m.FromEmail)
	assert.Equal(t, "Test Sender", m.FromName)
	assert.Equal(t, "support@test.com", m.ReplyTo)
	assert.Equal(t, "https://test.com", m.SiteURL)
}

// TestNewMailerFromEnv_EmptyValues tests with empty string values
func TestNewMailerFromEnv_EmptyValues(t *testing.T) {
	os.Setenv("SMTP_HOST", "")
	os.Setenv("SMTP_PORT", "")
	os.Setenv("NO_REPLY_EMAIL", "")
	defer cleanupEnv()

	m := mailer.NewMailerFromEnv()

	assert.Nil(t, m)
}

// TestNewMailerFromEnv_PortEdgeCases tests various port edge cases
func TestNewMailerFromEnv_PortEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		portValue    string
		expectedPort int
	}{
		{"Standard SMTP", "25", 25},
		{"Submission", "587", 587},
		{"SMTPS", "465", 465},
		{"Custom high port", "2525", 2525},
		{"Invalid text", "abc", 587},
		{"Empty", "", 587},
		{"Zero", "0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("SMTP_HOST", "smtp.example.com")
			os.Setenv("SMTP_PORT", tt.portValue)
			os.Setenv("NO_REPLY_EMAIL", "noreply@example.com")
			defer cleanupEnv()

			m := mailer.NewMailerFromEnv()

			if tt.portValue == "" {
				assert.Nil(t, m)
			} else {
				require.NotNil(t, m)
				assert.Equal(t, tt.expectedPort, m.Port)
			}
		})
	}
}

// TestSendEmail_DifferentPorts tests SendEmail with different port numbers
func TestSendEmail_DifferentPorts(t *testing.T) {
	ports := []int{25, 465, 587, 2525}

	for _, port := range ports {
		m := &mailer.Mailer{
			Host:      "invalid.smtp.server",
			Port:      port,
			FromEmail: "noreply@example.com",
		}

		err := m.SendEmail("to@example.com", "Test", "<p>Body</p>")

		// All should fail but with different port numbers
		assert.Error(t, err)
	}
}

// TestSendInvite_SpecialCharacters tests SendInvite with special characters in name
func TestSendInvite_SpecialCharacters(t *testing.T) {
	m := &mailer.Mailer{
		Host:      "invalid.smtp.server",
		Port:      587,
		FromEmail: "noreply@example.com",
	}

	names := []string{
		"John O'Brien",
		"José García",
		"François Müller",
		"李明",
		"User@123",
	}

	for _, name := range names {
		err := m.SendInvite("to@example.com", name, "/reset", "temp123")
		// Should handle special characters without panicking
		assert.Error(t, err) // Will fail SMTP but not panic
	}
}

// Helper function to cleanup environment variables
func cleanupEnv() {
	os.Unsetenv("SMTP_HOST")
	os.Unsetenv("SMTP_PORT")
	os.Unsetenv("SMTP_USER")
	os.Unsetenv("SMTP_PASS")
	os.Unsetenv("NO_REPLY_EMAIL")
	os.Unsetenv("NO_REPLY_NAME")
	os.Unsetenv("SUPPORT_EMAIL")
	os.Unsetenv("SITE_URL")
}
