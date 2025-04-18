package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/sirupsen/logrus"
)

// DomainState holds per-domain notification flags and expiry
type DomainState struct {
	Expiration        time.Time `json:"expiration"`
	NotifiedExpiry    bool      `json:"notified_expiry"`
	NotifiedAvailable bool      `json:"notified_available"`
}

var (
	domains       []string
	thresholdDays int
	stateDir      string

	smtpHost  string
	smtpPort  int
	smtpUser  string
	smtpPass  string
	emailFrom string
	emailTo   string

	log = logrus.New()
)

func init() {
	// set log level based on DEBUG env
	if os.Getenv("DEBUG") == "true" {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}

	// debug environment
	log.Infof("Starting Domain Checker")
	log.Debugf("Env DOMAINS=%q", os.Getenv("DOMAINS"))
	log.Debugf("Env STATE_DIR=%q", os.Getenv("STATE_DIR"))
	log.Debugf("Env THRESHOLD_DAYS=%q", os.Getenv("THRESHOLD_DAYS"))
	log.Debugf("Env SMTP_HOST=%q", os.Getenv("SMTP_HOST"))
	log.Debugf("Env SMTP_PORT=%q", os.Getenv("SMTP_PORT"))
	log.Debugf("Env SMTP_USER=%q", os.Getenv("SMTP_USER"))
	log.Debugf("Env EMAIL_FROM=%q", os.Getenv("EMAIL_FROM"))
	log.Debugf("Env EMAIL_TO=%q", os.Getenv("EMAIL_TO"))

	// parse environment variables
	domains = strings.Split(os.Getenv("DOMAINS"), ",")
	var err error
	thresholdDays, err = strconv.Atoi(os.Getenv("THRESHOLD_DAYS"))
	if err != nil || thresholdDays < 1 {
		thresholdDays = 7
	}
	stateDir = os.Getenv("STATE_DIR")
	if stateDir == "" {
		stateDir = "/data"
	}

	smtpHost = strings.TrimSpace(os.Getenv("SMTP_HOST"))
	smtpPort, _ = strconv.Atoi(os.Getenv("SMTP_PORT"))
	smtpUser = strings.TrimSpace(os.Getenv("SMTP_USER"))
	smtpPass = os.Getenv("SMTP_PASS")
	emailFrom = strings.TrimSpace(os.Getenv("EMAIL_FROM"))
	emailTo = strings.TrimSpace(os.Getenv("EMAIL_TO"))
}

func main() {
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		log.Fatalf("Failed to create state directory %s: %v", stateDir, err)
	}
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		processDomain(domain)
	}
}

func processDomain(domain string) {
	log.Infof("Checking %s", domain)
	state := loadState(domain)

	// DNS availability filter
	if _, err := net.LookupHost(domain); err != nil {
		log.Infof("→ DNS NXDOMAIN for %s, likely available", domain)
		if !state.NotifiedAvailable {
			notify(domain, fmt.Sprintf("Domain %s is now available!", domain))
			state.NotifiedAvailable = true
		}
		saveState(domain, state)
		return
	}

	// WHOIS expiry check
	whoisRaw, err := whois.Whois(domain)
	if err != nil {
		log.Warnf("WHOIS lookup failed for %s: %v", domain, err)
		return
	}
	parsed, err := whoisparser.Parse(whoisRaw)
	if err != nil {
		log.Warnf("WHOIS parse failed for %s: %v", domain, err)
		return
	}

	expDate, err := parseExpiration(parsed.Domain.ExpirationDate)
	if err != nil {
		log.Warnf("Could not parse expiration date for %s: %v", domain, err)
		return
	}
	log.Infof("→ %s expires at %s", domain, expDate.Format(time.RFC3339))

	daysLeft := int(time.Until(expDate).Hours() / 24)
	if daysLeft <= thresholdDays && !state.NotifiedExpiry {
		notify(domain, fmt.Sprintf("Domain %s expires in %d days", domain, daysLeft))
		state.NotifiedExpiry = true
	}
	state.Expiration = expDate
	saveState(domain, state)
}

// parseExpiration tries RFC3339 then date-only formats
func parseExpiration(raw string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", raw)
}

func stateFilePath(domain string) string {
	safe := strings.ReplaceAll(domain, ".", "_")
	return filepath.Join(stateDir, safe+".json")
}

func loadState(domain string) DomainState {
	path := stateFilePath(domain)
	var st DomainState
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("Failed to read state file for %s: %v", domain, err)
		}
		return st
	}
	if err := json.Unmarshal(data, &st); err != nil {
		log.Warnf("Failed to parse state file for %s: %v", domain, err)
	}
	return st
}

func saveState(domain string, st DomainState) {
	path := stateFilePath(domain)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		log.Errorf("Failed to marshal state for %s: %v", domain, err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Warnf("Failed to write state file for %s: %v", domain, err)
	}
}

func notify(domain, message string) {
	log.Infof("Notification for %s: %s", domain, message)
	if smtpHost == "" || emailFrom == "" || emailTo == "" {
		log.Infof("SMTP not configured, skipping email send")
		return
	}
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", emailFrom, emailTo, message, message))
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
	if err := smtp.SendMail(addr, auth, emailFrom, []string{emailTo}, msg); err != nil {
		log.Errorf("Failed to send mail for %s: %v", domain, err)
	}
}
