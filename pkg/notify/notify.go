// Package notify provides notification functionality for the domain checker application
package notify

import (
	"fmt"
	"net/smtp"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

// Notifier handles notification operations
type Notifier struct {
	cfg *config.Config
	log *logger.Logger
}

// New creates a new notifier
func New(cfg *config.Config, log *logger.Logger) *Notifier {
	return &Notifier{
		cfg: cfg,
		log: log,
	}
}

// Send sends an email notification or logs if SMTP is not configured
// It takes the domain name and message to send
func (n *Notifier) Send(domain, message string) {
	n.log.Infof("Notification for %s: %s", domain, message)

	// Check if SMTP is configured
	if n.cfg.SMTPHost == "" || n.cfg.EmailFrom == "" || n.cfg.EmailTo == "" {
		n.log.Infof("SMTP not configured, skipping email send")
		return
	}

	// Prepare email
	auth := smtp.PlainAuth("", n.cfg.SMTPUser, n.cfg.SMTPPass, n.cfg.SMTPHost)

	// Format email with headers and body
	msg := []byte(fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"\r\n"+
			"%s\r\n",
		n.cfg.EmailFrom,
		n.cfg.EmailTo,
		message,
		message,
	))

	// Send email
	addr := fmt.Sprintf("%s:%d", n.cfg.SMTPHost, n.cfg.SMTPPort)
	if err := smtp.SendMail(addr, auth, n.cfg.EmailFrom, []string{n.cfg.EmailTo}, msg); err != nil {
		n.log.Errorf("Failed to send mail for %s: %v", domain, err)
	} else {
		n.log.Infof("Email notification sent successfully for %s", domain)
	}
}