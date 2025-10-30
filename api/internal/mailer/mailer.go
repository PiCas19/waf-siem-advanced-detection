package mailer

import (
    "fmt"
    "os"
    "strconv"
    "strings"

    gomail "gopkg.in/gomail.v2"
)

// Mailer holds SMTP configuration
type Mailer struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string
    SiteURL  string // e.g. https://dashboard.example.com
}

// NewMailerFromEnv builds a Mailer from environment variables.
// Required env vars: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, NO_REPLY_EMAIL, SITE_URL
func NewMailerFromEnv() *Mailer {
    host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
    portStr := strings.TrimSpace(os.Getenv("SMTP_PORT"))
    user := strings.TrimSpace(os.Getenv("SMTP_USER"))
    pass := strings.TrimSpace(os.Getenv("SMTP_PASS"))
    from := strings.TrimSpace(os.Getenv("NO_REPLY_EMAIL"))
    site := strings.TrimSpace(os.Getenv("SITE_URL"))

    if host == "" || portStr == "" || from == "" {
        // Not configured
        return nil
    }

    port, err := strconv.Atoi(portStr)
    if err != nil {
        port = 587
    }

    return &Mailer{
        Host:     host,
        Port:     port,
        Username: user,
        Password: pass,
        From:     from,
        SiteURL:  site,
    }
}

// SendInvite sends an invitation email with reset link and temporary password.
func (m *Mailer) SendInvite(toEmail, fullName, resetLink, tempPassword string) error {
    if m == nil {
        return fmt.Errorf("mailer not configured")
    }

    subject := "[no-reply] Your account on WAF Dashboard"

    fullLink := resetLink
    if m.SiteURL != "" && !strings.HasPrefix(resetLink, "http") {
        // ensure proper slash
        prefix := strings.TrimRight(m.SiteURL, "/")
        if strings.HasPrefix(resetLink, "/") {
            fullLink = prefix + resetLink
        } else {
            fullLink = prefix + "/" + resetLink
        }
    }

    html := fmt.Sprintf(`<p>Hello %s,</p>
<p>An administrator has created an account for you on the WAF Dashboard.</p>
<p>Your temporary password is: <strong>%s</strong></p>
<p>Please click the link below to set your password (link expires in 24 hours):</p>
<p><a href="%s">Set your password</a></p>
<p>If you did not expect this email, please contact your administrator.</p>
<p>-- WAF Dashboard (no-reply)</p>`, fullName, tempPassword, fullLink)

    plain := fmt.Sprintf("Hello %s,\n\nAn administrator created an account for you. Temporary password: %s\nSet your password: %s\n\n-- WAF Dashboard (no-reply)", fullName, tempPassword, fullLink)

    msg := gomail.NewMessage()
    msg.SetHeader("From", m.From)
    msg.SetHeader("To", toEmail)
    msg.SetHeader("Subject", subject)
    msg.SetBody("text/plain", plain)
    msg.AddAlternative("text/html", html)

    d := gomail.NewDialer(m.Host, m.Port, m.Username, m.Password)
    // If SMTP_USER/PASS empty, dialer will attempt unauthenticated send

    return d.DialAndSend(msg)
}
