// Package main provides a domain monitoring tool that checks for domain availability
// and expiration dates, sending notifications when domains are available or about to expire.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
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
}

// DomainState holds per-domain flags and expiry
type DomainState struct {
	// Domain expiration date
	Expiration time.Time `json:"expiration"`

	// Whether we've already notified about expiry
	NotifiedExpiry bool `json:"notified_expiry"`

	// Whether we've already notified about availability
	NotifiedAvailable bool `json:"notified_available"`
}

// Function types for easier testing
type (
	NotifyFunc         func(domain, message string)
	CheckAvailableFunc func(domain string) (bool, error)
	RetryWHOISFunc     func(domain string) string
)

// Logger is a simple logging interface that replaces logrus
type Logger struct {
	debugEnabled bool
}

// Debugf logs debug messages when debug is enabled
func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.debugEnabled {
		fmt.Fprintf(os.Stderr, "DEBUG: "+format+"\n", args...)
	}
}

// Infof logs informational messages
func (l *Logger) Infof(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, "INFO: "+format+"\n", args...)
}

// Warnf logs warning messages
func (l *Logger) Warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARN: "+format+"\n", args...)
}

// Errorf logs error messages
func (l *Logger) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
}

// Fatalf logs fatal messages and exits the program
func (l *Logger) Fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// Global variables
var (
	cfg Config
	log = &Logger{}
)

// Function variables that can be replaced in tests
var (
	notifyFn         NotifyFunc
	checkAvailableFn CheckAvailableFunc
	retryWHOISFn     RetryWHOISFunc
)

func init() {
	// Initialize function variables
	notifyFn = notify
	checkAvailableFn = checkAvailable
	retryWHOISFn = retryWHOIS

	// Initialize configuration
	initDefaults()
	loadFileConfig(os.Getenv("CONFIG_FILE"))
	overrideWithEnv()
	initLogger()
	cleanupState()
}

// initDefaults sets sensible defaults
func initDefaults() {
	cfg = Config{
		ThresholdDays: 7,
		StateDir:      "/data",
		Retries:       3,
		Backoff:       2 * time.Second,
		Concurrency:   5,
		Timeout:       5 * time.Second,
	}
}

// loadFileConfig loads JSON config if provided
func loadFileConfig(path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read config %s: %v", path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Invalid config in %s: %v", path, err)
	}
}

// overrideWithEnv overrides config with environment variables
func overrideWithEnv() {
	setStringList(&cfg.Domains, "DOMAINS", ",")
	setInt(&cfg.ThresholdDays, "THRESHOLD_DAYS")
	setString(&cfg.StateDir, "STATE_DIR")
	setString(&cfg.SMTPHost, "SMTP_HOST")
	setInt(&cfg.SMTPPort, "SMTP_PORT")
	setString(&cfg.SMTPUser, "SMTP_USER")
	setString(&cfg.SMTPPass, "SMTP_PASS")
	setString(&cfg.EmailFrom, "EMAIL_FROM")
	setString(&cfg.EmailTo, "EMAIL_TO")
	setInt(&cfg.Retries, "RETRIES")
	setDuration(&cfg.Backoff, "BACKOFF")
	setInt(&cfg.Concurrency, "CONCURRENCY")
	setDuration(&cfg.Timeout, "TIMEOUT")
}

// initLogger configures log level based on DEBUG env
func initLogger() {
	log.debugEnabled = strings.ToLower(os.Getenv("DEBUG")) == "true"
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

// processDomains processes all domains with controlled concurrency
func processDomains(domains []string, concurrency int) {
	// Create a semaphore to limit concurrency
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// Process each domain concurrently, but limited by the semaphore
	for _, d := range domains {
		domain := strings.TrimSpace(d)
		if domain == "" {
			log.Debugf("Skipping empty domain")
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(dom string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			processDomain(dom)
		}(domain)
	}

	// Wait for all goroutines to complete
	wg.Wait()
}

func main() {
	// Ensure state directory exists
	if err := os.MkdirAll(cfg.StateDir, 0755); err != nil {
		log.Fatalf("Failed to create state directory: %v", err)
	}

	log.Infof("Starting domain checker with %d domains", len(cfg.Domains))

	// Process all domains with configured concurrency
	processDomains(cfg.Domains, cfg.Concurrency)

	log.Infof("Domain checking completed")
}

// processDomain checks availability and expiry for a single domain
func processDomain(domain string) {
	log.Infof("Checking %s", domain)
	state := loadState(domain)

	// First check if the domain is available
	available, err := checkAvailableFn(domain)
	if err != nil {
		log.Warnf("DNS SOA lookup error for %s: %v", domain, err)
	} else if available {
		handleAvailable(domain, &state)
		return
	}

	// Check if we already have a valid expiration date
	hasValidExpiration := !state.Expiration.IsZero() && state.Expiration.After(time.Now())

	if !hasValidExpiration {
		// Only do WHOIS lookup if we don't have valid expiration info
		raw := retryWHOISFn(domain)
		if raw == "" {
			log.Warnf("Failed to get WHOIS data for %s", domain)
			return
		}

		parsed, err := whoisparser.Parse(raw)
		if err != nil {
			log.Warnf("WHOIS parse failed for %s: %v", domain, err)
			return
		}

		expDate, err := parseExpiration(parsed.Domain.ExpirationDate)
		if err != nil {
			log.Warnf("Invalid expiration date %q for %s", parsed.Domain.ExpirationDate, domain)
			return
		}

		// Save the expiration date in the state
		state.Expiration = expDate
		saveState(domain, state)
		handleExpiry(domain, expDate, &state)
	} else {
		// Use the cached expiration date
		handleExpiry(domain, state.Expiration, &state)
	}
}

// handleAvailable processes available domain notifications
func handleAvailable(domain string, state *DomainState) {
	log.Infof("→ %s is available", domain)
	if !state.NotifiedAvailable {
		notifyFn(domain, fmt.Sprintf("Domain %s is now available!", domain))
		state.NotifiedAvailable = true
		saveState(domain, *state)
	}
}

// handleExpiry processes expiry notifications
func handleExpiry(domain string, expDate time.Time, state *DomainState) {
	log.Infof("→ %s expires at %s", domain, expDate.Format(time.RFC3339))
	daysLeft := int(time.Until(expDate).Hours() / 24)
	if daysLeft <= cfg.ThresholdDays && !state.NotifiedExpiry {
		notifyFn(domain, fmt.Sprintf("Domain %s expires in %d days", domain, daysLeft))
		state.NotifiedExpiry = true
		saveState(domain, *state)
	}
}

// checkAvailable does DNS SOA lookup with context timeout
// Returns true if the domain is available (no SOA record found)
func checkAvailable(domain string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)

	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return false, fmt.Errorf("failed to read DNS config: %w", err)
	}

	resp, _, err := c.ExchangeContext(ctx, &m, net.JoinHostPort(conf.Servers[0], conf.Port))
	if err != nil {
		return false, fmt.Errorf("DNS query failed: %w", err)
	}

	// Domain is available if there's no SOA record
	return len(resp.Answer) == 0, nil
}

// retryWHOIS performs WHOIS lookup with retries and exponential backoff
// Returns the raw WHOIS data or empty string if all retries failed
func retryWHOIS(domain string) string {
	var raw string
	var err error

	for i, backoff := 0, cfg.Backoff; i < cfg.Retries; i, backoff = i+1, backoff*2 {
		raw, err = whois.Whois(domain)
		if err == nil {
			return raw
		}

		log.Debugf("WHOIS retry %d for %s: %v", i+1, domain, err)

		// Add jitter to backoff to prevent thundering herd
		jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
		time.Sleep(backoff + jitter)
	}

	log.Warnf("WHOIS failed for %s after %d retries: %v", domain, cfg.Retries, err)
	return ""
}

// parseExpiration tries RFC3339 then date-only formats
func parseExpiration(raw string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", raw)
}

// stateFilePath returns the JSON path for a domain
func stateFilePath(domain string) string {
	safe := strings.ReplaceAll(domain, ".", "_")
	return filepath.Join(cfg.StateDir, safe+".json")
}

// loadState reads state, logs errors
func loadState(domain string) DomainState {
	path := stateFilePath(domain)
	var st DomainState
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			log.Warnf("Parse state error for %s: %v", domain, err)
		}
	}
	return st
}

// saveState writes state file
func saveState(domain string, st DomainState) {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		log.Errorf("Marshal state error for %s: %v", domain, err)
		return
	}
	if err := os.WriteFile(stateFilePath(domain), data, 0644); err != nil {
		log.Warnf("Write state error for %s: %v", domain, err)
	}
}

// isAppGeneratedFile checks if a file was generated by this application
// by attempting to parse it as a DomainState JSON
func isAppGeneratedFile(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var state DomainState
	if err := json.Unmarshal(data, &state); err != nil {
		return false
	}

	// Additional validation could be added here if needed
	// For example, checking if specific fields have valid values

	return true
}

// cleanupState removes files not in current domain list
func cleanupState() {
	files, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		log.Warnf("Could not read state dir %s: %v", cfg.StateDir, err)
		return
	}
	keep := make(map[string]struct{}, len(cfg.Domains))
	for _, d := range cfg.Domains {
		keep[strings.ReplaceAll(strings.TrimSpace(d), ".", "_")] = struct{}{}
	}
	for _, f := range files {
		// Only process files with .json extension
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}

		base := strings.TrimSuffix(f.Name(), ".json")
		if _, ok := keep[base]; !ok {
			path := filepath.Join(cfg.StateDir, f.Name())

			// Verify this is a file created by our app by checking if it's a valid DomainState JSON
			if isAppGeneratedFile(path) {
				if err := os.Remove(path); err != nil {
					log.Warnf("Failed to remove stale %s: %v", path, err)
				} else {
					log.Infof("Removed stale state %s", path)
				}
			} else {
				log.Debugf("Skipping non-app file: %s", path)
			}
		}
	}
}

// notify sends an email notification or logs if SMTP is not configured
// It takes the domain name and message to send
func notify(domain, message string) {
	log.Infof("Notification for %s: %s", domain, message)

	// Check if SMTP is configured
	if cfg.SMTPHost == "" || cfg.EmailFrom == "" || cfg.EmailTo == "" {
		log.Infof("SMTP not configured, skipping email send")
		return
	}

	// Prepare email
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	// Format email with headers and body
	msg := []byte(fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"\r\n"+
			"%s\r\n",
		cfg.EmailFrom,
		cfg.EmailTo,
		message,
		message,
	))

	// Send email
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	if err := smtp.SendMail(addr, auth, cfg.EmailFrom, []string{cfg.EmailTo}, msg); err != nil {
		log.Errorf("Failed to send mail for %s: %v", domain, err)
	} else {
		log.Infof("Email notification sent successfully for %s", domain)
	}
}
