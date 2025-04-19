// Package whois provides WHOIS lookup functionality for the domain checker application
package whois

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	
	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

// Checker handles WHOIS operations
type Checker struct {
	cfg *config.Config
	log *logger.Logger
}

// New creates a new WHOIS checker
func New(cfg *config.Config, log *logger.Logger) *Checker {
	return &Checker{
		cfg: cfg,
		log: log,
	}
}

// QueryWithRetries performs WHOIS lookup with retries and exponential backoff
// Returns the raw WHOIS data or empty string if all retries failed
func (c *Checker) QueryWithRetries(domain string) string {
	var raw string
	var err error

	for i, backoff := 0, c.cfg.Backoff; i < c.cfg.Retries; i, backoff = i+1, backoff*2 {
		raw, err = whois.Whois(domain)
		if err == nil {
			return raw
		}

		c.log.Debugf("WHOIS retry %d for %s: %v", i+1, domain, err)

		// Add jitter to backoff to prevent thundering herd
		jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
		time.Sleep(backoff + jitter)
	}

	c.log.Warnf("WHOIS failed for %s after %d retries: %v", domain, c.cfg.Retries, err)
	return ""
}

// ParseExpiration tries RFC3339 then date-only formats
func (c *Checker) ParseExpiration(raw string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", raw)
}

// GetExpirationDate gets the expiration date for a domain
func (c *Checker) GetExpirationDate(domain string) (time.Time, error) {
	raw := c.QueryWithRetries(domain)
	if raw == "" {
		return time.Time{}, fmt.Errorf("failed to get WHOIS data")
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("WHOIS parse failed: %w", err)
	}

	return c.ParseExpiration(parsed.Domain.ExpirationDate)
}