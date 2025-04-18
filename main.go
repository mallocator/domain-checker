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
	"github.com/sirupsen/logrus"
)

// Config holds application settings
type Config struct {
	Domains       []string      `json:"domains"`
	ThresholdDays int           `json:"threshold_days"`
	StateDir      string        `json:"state_dir"`
	SMTPHost      string        `json:"smtp_host"`
	SMTPPort      int           `json:"smtp_port"`
	SMTPUser      string        `json:"smtp_user"`
	SMTPPass      string        `json:"smtp_pass"`
	EmailFrom     string        `json:"email_from"`
	EmailTo       string        `json:"email_to"`
	Retries       int           `json:"retries"`
	Backoff       time.Duration `json:"backoff"` // initial backoff
	Concurrency   int           `json:"concurrency"`
	Timeout       time.Duration `json:"timeout"` // per lookup timeout
}

// DomainState holds per-domain flags and expiry
type DomainState struct {
	Expiration        time.Time `json:"expiration"`
	NotifiedExpiry    bool      `json:"notified_expiry"`
	NotifiedAvailable bool      `json:"notified_available"`
}

var (
	cfg Config
	log = logrus.New()
)

func init() {
	initDefaults()
	loadFileConfig(os.Getenv("CONFIG_FILE"))
	overrideWithEnv()
	initLogger()
	log.Infof("Final config: %+v", cfg)
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
	if strings.ToLower(os.Getenv("DEBUG")) == "true" {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}
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

func main() {
	if err := os.MkdirAll(cfg.StateDir, 0755); err != nil {
		log.Fatalf("Failed to create state directory: %v", err)
	}

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, d := range cfg.Domains {
		domain := strings.TrimSpace(d)
		if domain == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(dom string) {
			defer wg.Done()
			defer func() { <-sem }()
			processDomain(dom)
		}(domain)
	}
	wg.Wait()
}

// processDomain checks availability and expiry
func processDomain(domain string) {
	log.Infof("Checking %s", domain)
	state := loadState(domain)

	if available, err := checkAvailable(domain); err != nil {
		log.Warnf("DNS SOA lookup error for %s: %v", domain, err)
	} else if available {
		handleAvailable(domain, &state)
		return
	}

	raw := retryWHOIS(domain)
	if raw == "" {
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
	handleExpiry(domain, expDate, &state)
}

// handleAvailable processes available domain notifications
func handleAvailable(domain string, state *DomainState) {
	log.Infof("→ %s is available", domain)
	if !state.NotifiedAvailable {
		notify(domain, fmt.Sprintf("Domain %s is now available!", domain))
		state.NotifiedAvailable = true
		saveState(domain, *state)
	}
}

// handleExpiry processes expiry notifications
func handleExpiry(domain string, expDate time.Time, state *DomainState) {
	log.Infof("→ %s expires at %s", domain, expDate.Format(time.RFC3339))
	daysLeft := int(time.Until(expDate).Hours() / 24)
	if daysLeft <= cfg.ThresholdDays && !state.NotifiedExpiry {
		notify(domain, fmt.Sprintf("Domain %s expires in %d days", domain, daysLeft))
		state.NotifiedExpiry = true
		saveState(domain, *state)
	}
}

// checkAvailable does DNS SOA lookup with context timeout
func checkAvailable(domain string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return false, err
	}
	resp, _, err := c.ExchangeContext(ctx, &m, net.JoinHostPort(conf.Servers[0], conf.Port))
	if err != nil {
		return false, err
	}
	return len(resp.Answer) == 0, nil
}

// retryWHOIS performs WHOIS lookup with retries and backoff
func retryWHOIS(domain string) string {
	var raw string
	var err error
	for i, backoff := 0, cfg.Backoff; i < cfg.Retries; i, backoff = i+1, backoff*2 {
		raw, err = whois.Whois(domain)
		if err == nil {
			return raw
		}
		log.Debugf("WHOIS retry %d for %s: %v", i+1, domain, err)
		time.Sleep(backoff + time.Duration(rand.Intn(1000))*time.Millisecond)
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

// notify sends an email or logs skip
func notify(domain, message string) {
	log.Infof("Notification for %s: %s", domain, message)
	if cfg.SMTPHost == "" || cfg.EmailFrom == "" || cfg.EmailTo == "" {
		log.Infof("SMTP not configured, skipping email send")
		return
	}
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		cfg.EmailFrom, cfg.EmailTo, message, message))
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	if err := smtp.SendMail(addr, auth, cfg.EmailFrom, []string{cfg.EmailTo}, msg); err != nil {
		log.Errorf("Failed to send mail for %s: %v", domain, err)
	}
}
