// Package config provides configuration handling for the domain checker application
package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mallocator/domain-checker/pkg/logger"
)

// Config holds application settings
type Config struct {
	// List of domains to monitor
	Domains []string `json:"domains"`

	// Number of days before expiration to send notification
	ThresholdDays int `json:"threshold_days"`

	// Directory to store state files
	StateDir string `json:"state_dir"`

	// SMTP configuration for email notifications
	SMTPHost  string `json:"smtp_host"`
	SMTPPort  int    `json:"smtp_port"`
	SMTPUser  string `json:"smtp_user"`
	SMTPPass  string `json:"smtp_pass"`
	EmailFrom string `json:"email_from"`
	EmailTo   string `json:"email_to"`

	// Retry configuration
	Retries int           `json:"retries"`
	Backoff time.Duration `json:"backoff"` // initial backoff duration

	// Concurrency and timeout settings
	Concurrency int           `json:"concurrency"`
	Timeout     time.Duration `json:"timeout"` // per lookup timeout

	// Logger instance
	Log *logger.Logger
}

// New creates a new configuration with default values
func New(log *logger.Logger) *Config {
	cfg := &Config{
		ThresholdDays: 7,
		StateDir:      "/data",
		Retries:       3,
		Backoff:       2 * time.Second,
		Concurrency:   5,
		Timeout:       5 * time.Second,
		Log:           log,
	}

	return cfg
}

// LoadFromFile loads configuration from a JSON file
func (c *Config) LoadFromFile(path string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, c); err != nil {
		return err
	}

	return nil
}

// LoadFromEnv overrides configuration with environment variables
func (c *Config) LoadFromEnv() {
	setStringList(&c.Domains, "DOMAINS", ",")
	setInt(&c.ThresholdDays, "THRESHOLD_DAYS")
	setString(&c.StateDir, "STATE_DIR")
	setString(&c.SMTPHost, "SMTP_HOST")
	setInt(&c.SMTPPort, "SMTP_PORT")
	setString(&c.SMTPUser, "SMTP_USER")
	setString(&c.SMTPPass, "SMTP_PASS")
	setString(&c.EmailFrom, "EMAIL_FROM")
	setString(&c.EmailTo, "EMAIL_TO")
	setInt(&c.Retries, "RETRIES")
	setDuration(&c.Backoff, "BACKOFF")
	setInt(&c.Concurrency, "CONCURRENCY")
	setDuration(&c.Timeout, "TIMEOUT")
}

// setStringList sets a []string from env split by sep
func setStringList(field *[]string, env, sep string) {
	if v := os.Getenv(env); v != "" {
		*field = strings.Split(v, sep)
	}
}

// setString sets a string field from env
func setString(field *string, env string) {
	if v := os.Getenv(env); v != "" {
		*field = strings.TrimSpace(v)
	}
}

// setInt sets an int field from env
func setInt(field *int, env string) {
	if v := os.Getenv(env); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			*field = i
		}
	}
}

// setDuration sets a time.Duration field from env
func setDuration(field *time.Duration, env string) {
	if v := os.Getenv(env); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*field = d
		}
	}
}
