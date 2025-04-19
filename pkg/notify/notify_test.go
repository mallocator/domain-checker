package notify

import (
	"testing"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

func TestNew(t *testing.T) {
	// Create a logger and config
	log := logger.New()
	cfg := config.New(log)

	// Create a notifier
	notifier := New(cfg, log)

	// Verify that the notifier was created correctly
	if notifier == nil {
		t.Errorf("Expected notifier to be created, got nil")
		return
	}
	if notifier.cfg != cfg {
		t.Errorf("Expected notifier.cfg to be %v, got %v", cfg, notifier.cfg)
	}
	if notifier.log != log {
		t.Errorf("Expected notifier.log to be %v, got %v", log, notifier.log)
	}
}

func TestSend_NoSMTPConfig(t *testing.T) {
	// Create a logger and config
	log := logger.New()

	// Create a config with no SMTP settings
	cfg := &config.Config{
		SMTPHost:  "",
		EmailFrom: "",
		EmailTo:   "",
	}

	// Create a notifier
	notifier := New(cfg, log)

	// Call the Send function
	domain := "example.com"
	message := "Test message"

	// This should not panic and just log a message
	notifier.Send(domain, message)

	// We can't easily verify the log output in this test framework
	// In a real test, we would capture stdout/stderr or use a mock logger
}

func TestSend_WithSMTPConfig(t *testing.T) {
	// Create a logger and config
	log := logger.New()

	// Create a config with SMTP settings
	cfg := &config.Config{
		SMTPHost:  "smtp.example.com",
		SMTPPort:  25,
		SMTPUser:  "user",
		SMTPPass:  "pass",
		EmailFrom: "from@example.com",
		EmailTo:   "to@example.com",
	}

	// Create a notifier
	notifier := New(cfg, log)

	// Call the Send function
	domain := "example.com"
	message := "Test message"

	// This should not panic, but will fail to send email with fake settings
	notifier.Send(domain, message)

	// We can't easily verify the log output in this test framework
	// In a real test, we would capture stdout/stderr or use a mock logger
}
