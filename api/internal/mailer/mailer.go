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
    FromEmail string
    FromName  string
    ReplyTo   string
    SiteURL  string // e.g. https://dashboard.example.com
}

// NewMailerFromEnv builds a Mailer from environment variables.
// Expected env vars:
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
//   NO_REPLY_EMAIL (email address used as From)
//   NO_REPLY_NAME (optional display name for From)
//   SUPPORT_EMAIL (optional Reply-To address)
//   SITE_URL
func NewMailerFromEnv() *Mailer {
    host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
    portStr := strings.TrimSpace(os.Getenv("SMTP_PORT"))
    user := strings.TrimSpace(os.Getenv("SMTP_USER"))
    pass := strings.TrimSpace(os.Getenv("SMTP_PASS"))
    from := strings.TrimSpace(os.Getenv("NO_REPLY_EMAIL"))
    fromName := strings.TrimSpace(os.Getenv("NO_REPLY_NAME"))
    replyTo := strings.TrimSpace(os.Getenv("SUPPORT_EMAIL"))
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
        Host:      host,
        Port:      port,
        Username:  user,
        Password:  pass,
        FromEmail: from,
        FromName:  fromName,
        ReplyTo:   replyTo,
        SiteURL:   site,
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
    // Format From header: "Name <email>" if a name is provided
    fromHeader := m.FromEmail
    if m.FromName != "" {
        fromHeader = fmt.Sprintf("%s <%s>", m.FromName, m.FromEmail)
    }
    msg.SetHeader("From", fromHeader)
    if m.ReplyTo != "" {
        msg.SetHeader("Reply-To", m.ReplyTo)
    }
    msg.SetHeader("To", toEmail)
    msg.SetHeader("Subject", subject)
    msg.SetBody("text/plain", plain)
    msg.AddAlternative("text/html", html)

    d := gomail.NewDialer(m.Host, m.Port, m.Username, m.Password)
    // If SMTP_USER/PASS empty, dialer will attempt unauthenticated send

    return d.DialAndSend(msg)
}
