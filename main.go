// Package main provides a domain monitoring tool that checks for domain availability
// and expiration dates, sending notifications when domains are available or about to expire.
package main

import (
	"os"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/dns"
	"github.com/mallocator/domain-checker/pkg/domain"
	"github.com/mallocator/domain-checker/pkg/logger"
	"github.com/mallocator/domain-checker/pkg/notify"
	"github.com/mallocator/domain-checker/pkg/state"
	"github.com/mallocator/domain-checker/pkg/whois"
)

func main() {
	// Initialize logger
	log := logger.New()

	// Initialize configuration
	cfg := config.New(log)
	if err := cfg.LoadFromFile(os.Getenv("CONFIG_FILE")); err != nil {
		log.Fatalf("Failed to load config file: %v", err)
	}
	cfg.LoadFromEnv()

	// Ensure state directory exists
	if err := os.MkdirAll(cfg.StateDir, 0755); err != nil {
		log.Fatalf("Failed to create state directory: %v", err)
	}

	// Initialize components
	stateManager := state.New(cfg, log)
	dnsChecker := dns.New(cfg, log)
	whoisChecker := whois.New(cfg, log)
	notifier := notify.New(cfg, log)

	// Clean up state files
	stateManager.Cleanup()

	// Initialize domain processor
	processor := domain.New(cfg, log, dnsChecker, whoisChecker, notifier, stateManager)

	log.Infof("Starting domain checker with %d domains", len(cfg.Domains))

	// Process all domains
	processor.ProcessAll()

	log.Infof("Domain checking completed")
}
