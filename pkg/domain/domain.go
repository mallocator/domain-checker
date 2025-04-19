// Package domain provides domain processing functionality for the domain checker application
package domain

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/dns"
	"github.com/mallocator/domain-checker/pkg/logger"
	"github.com/mallocator/domain-checker/pkg/notify"
	"github.com/mallocator/domain-checker/pkg/state"
	"github.com/mallocator/domain-checker/pkg/whois"
)

// Processor handles domain processing operations
type Processor struct {
	cfg      *config.Config
	log      *logger.Logger
	dns      *dns.Checker
	whois    *whois.Checker
	notifier *notify.Notifier
	state    *state.Manager
}

// New creates a new domain processor
func New(cfg *config.Config, log *logger.Logger, dnsChecker *dns.Checker, 
	whoisChecker *whois.Checker, notifier *notify.Notifier, stateManager *state.Manager) *Processor {
	return &Processor{
		cfg:      cfg,
		log:      log,
		dns:      dnsChecker,
		whois:    whoisChecker,
		notifier: notifier,
		state:    stateManager,
	}
}

// ProcessAll processes all domains with controlled concurrency
func (p *Processor) ProcessAll() {
	// Create a semaphore to limit concurrency
	sem := make(chan struct{}, p.cfg.Concurrency)
	var wg sync.WaitGroup

	// Process each domain concurrently, but limited by the semaphore
	for _, d := range p.cfg.Domains {
		domain := strings.TrimSpace(d)
		if domain == "" {
			p.log.Debugf("Skipping empty domain")
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(dom string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			p.ProcessDomain(dom)
		}(domain)
	}

	// Wait for all goroutines to complete
	wg.Wait()
}

// ProcessDomain checks availability and expiry for a single domain
func (p *Processor) ProcessDomain(domain string) {
	p.log.Infof("Checking %s", domain)
	domainState := p.state.Load(domain)

	// First check if the domain is available
	available, err := p.dns.IsAvailable(domain)
	if err != nil {
		p.log.Warnf("DNS SOA lookup error for %s: %v", domain, err)
	} else if available {
		p.handleAvailable(domain, &domainState)
		return
	}

	// Check if we already have a valid expiration date
	hasValidExpiration := !domainState.Expiration.IsZero() && domainState.Expiration.After(time.Now())

	if !hasValidExpiration {
		// Get expiration date from WHOIS
		expDate, err := p.whois.GetExpirationDate(domain)
		if err != nil {
			p.log.Warnf("Failed to get expiration date for %s: %v", domain, err)
			return
		}

		// Save the expiration date in the state
		domainState.Expiration = expDate
		p.state.Save(domain, domainState)
		p.handleExpiry(domain, expDate, &domainState)
	} else {
		// Use the cached expiration date
		p.handleExpiry(domain, domainState.Expiration, &domainState)
	}
}

// handleAvailable processes available domain notifications
func (p *Processor) handleAvailable(domain string, state *state.DomainState) {
	p.log.Infof("→ %s is available", domain)
	if !state.NotifiedAvailable {
		p.notifier.Send(domain, fmt.Sprintf("Domain %s is now available!", domain))
		state.NotifiedAvailable = true
		p.state.Save(domain, *state)
	}
}

// handleExpiry processes expiry notifications
func (p *Processor) handleExpiry(domain string, expDate time.Time, state *state.DomainState) {
	p.log.Infof("→ %s expires at %s", domain, expDate.Format(time.RFC3339))
	daysLeft := int(time.Until(expDate).Hours() / 24)
	if daysLeft <= p.cfg.ThresholdDays && !state.NotifiedExpiry {
		p.notifier.Send(domain, fmt.Sprintf("Domain %s expires in %d days", domain, daysLeft))
		state.NotifiedExpiry = true
		p.state.Save(domain, *state)
	}
}