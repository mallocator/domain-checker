package domain

import (
	"os"
	"testing"
	"time"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/dns"
	"github.com/mallocator/domain-checker/pkg/logger"
	"github.com/mallocator/domain-checker/pkg/notify"
	"github.com/mallocator/domain-checker/pkg/state"
	"github.com/mallocator/domain-checker/pkg/whois"
)

// TestNew tests the constructor function
func TestNew(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)
	dnsChecker := dns.New(cfg, log)
	whoisChecker := whois.New(cfg, log)
	notifier := notify.New(cfg, log)
	stateManager := state.New(cfg, log)

	processor := New(cfg, log, dnsChecker, whoisChecker, notifier, stateManager)

	if processor == nil {
		t.Errorf("Expected New to return a non-nil Processor")
		return
	}

	if processor.cfg != cfg {
		t.Errorf("Expected processor.cfg to be %v, got %v", cfg, processor.cfg)
	}

	if processor.log != log {
		t.Errorf("Expected processor.log to be %v, got %v", log, processor.log)
	}

	if processor.dns != dnsChecker {
		t.Errorf("Expected processor.dns to be %v, got %v", dnsChecker, processor.dns)
	}

	if processor.whois != whoisChecker {
		t.Errorf("Expected processor.whois to be %v, got %v", whoisChecker, processor.whois)
	}

	if processor.notifier != notifier {
		t.Errorf("Expected processor.notifier to be %v, got %v", notifier, processor.notifier)
	}

	if processor.state != stateManager {
		t.Errorf("Expected processor.state to be %v, got %v", stateManager, processor.state)
	}
}

// TestHandleAvailable tests the handleAvailable method
func TestHandleAvailable(t *testing.T) {
	// Create a temporary directory for state files
	tmpDir, err := os.MkdirTemp("", "domain_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("Failed to remove temporary directory: %v", err)
		}
	}()

	log := logger.New()
	cfg := config.New(log)
	cfg.StateDir = tmpDir

	// Create a notifier that we can track
	notifier := notify.New(cfg, log)
	stateManager := state.New(cfg, log)

	processor := &Processor{
		cfg:      cfg,
		log:      log,
		notifier: notifier,
		state:    stateManager,
	}

	// Test case 1: Domain is available and notification hasn't been sent
	domain := "example.com"
	domainState := &state.DomainState{NotifiedAvailable: false}

	// Call the method we're testing
	processor.handleAvailable(domain, domainState)

	// Verify the state was updated
	if !domainState.NotifiedAvailable {
		t.Errorf("Expected NotifiedAvailable to be true, got false")
	}

	// Test case 2: Domain is available but notification has already been sent
	domainState.NotifiedAvailable = true

	// Call the method again
	processor.handleAvailable(domain, domainState)

	// State should still be true
	if !domainState.NotifiedAvailable {
		t.Errorf("Expected NotifiedAvailable to still be true, got false")
	}
}

// TestHandleExpiry tests the handleExpiry method
func TestHandleExpiry(t *testing.T) {
	// Create a temporary directory for state files
	tmpDir, err := os.MkdirTemp("", "domain_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("Failed to remove temporary directory: %v", err)
		}
	}()

	log := logger.New()
	cfg := config.New(log)
	cfg.StateDir = tmpDir
	cfg.ThresholdDays = 30

	notifier := notify.New(cfg, log)
	stateManager := state.New(cfg, log)

	processor := &Processor{
		cfg:      cfg,
		log:      log,
		notifier: notifier,
		state:    stateManager,
	}

	domain := "example.com"

	// Test case 1: Domain expires soon and notification hasn't been sent
	expDate := time.Now().Add(time.Hour * 24 * 15) // 15 days from now
	domainState := &state.DomainState{NotifiedExpiry: false}

	processor.handleExpiry(domain, expDate, domainState)

	// Verify the state was updated
	if !domainState.NotifiedExpiry {
		t.Errorf("Expected NotifiedExpiry to be true, got false")
	}

	// Test case 2: Domain expires soon but notification has already been sent
	domainState.NotifiedExpiry = true

	processor.handleExpiry(domain, expDate, domainState)

	// State should still be true
	if !domainState.NotifiedExpiry {
		t.Errorf("Expected NotifiedExpiry to still be true, got false")
	}

	// Test case 3: Domain doesn't expire soon
	domainState.NotifiedExpiry = false
	expDate = time.Now().Add(time.Hour * 24 * 60) // 60 days from now

	processor.handleExpiry(domain, expDate, domainState)

	// State should not be updated
	if domainState.NotifiedExpiry {
		t.Errorf("Expected NotifiedExpiry to be false, got true")
	}
}

// TestProcessDomain tests the ProcessDomain method
// Note: This is a simplified test that doesn't make actual DNS or WHOIS queries
func TestProcessDomain(t *testing.T) {
	// Skip this test in normal runs since it would make external calls
	// Uncomment to run manually when needed
	t.Skip("Skipping TestProcessDomain as it would make external calls")

	// Create a temporary directory for state files
	tmpDir, err := os.MkdirTemp("", "domain_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("Failed to remove temporary directory: %v", err)
		}
	}()

	log := logger.New()
	cfg := config.New(log)
	cfg.StateDir = tmpDir

	dnsChecker := dns.New(cfg, log)
	whoisChecker := whois.New(cfg, log)
	notifier := notify.New(cfg, log)
	stateManager := state.New(cfg, log)

	processor := New(cfg, log, dnsChecker, whoisChecker, notifier, stateManager)

	// Test with a domain that likely exists
	domain := "example.com"
	processor.ProcessDomain(domain)

	// We can't easily assert on the results since we don't know the actual state
	// of the domain, but at least we can verify the function runs without errors
}

// TestProcessAll tests the ProcessAll method
// Note: This is a simplified test that doesn't make actual DNS or WHOIS queries
func TestProcessAll(t *testing.T) {
	// Skip this test in normal runs since it would make external calls
	// Uncomment to run manually when needed
	t.Skip("Skipping TestProcessAll as it would make external calls")

	// Create a temporary directory for state files
	tmpDir, err := os.MkdirTemp("", "domain_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("Failed to remove temporary directory: %v", err)
		}
	}()

	log := logger.New()
	cfg := config.New(log)
	cfg.StateDir = tmpDir
	cfg.Domains = []string{"example.com", "google.com", ""}
	cfg.Concurrency = 2

	dnsChecker := dns.New(cfg, log)
	whoisChecker := whois.New(cfg, log)
	notifier := notify.New(cfg, log)
	stateManager := state.New(cfg, log)

	processor := New(cfg, log, dnsChecker, whoisChecker, notifier, stateManager)

	// This is more of an integration test to ensure ProcessAll doesn't crash
	processor.ProcessAll()

	// We can't easily assert on the results since ProcessAll uses goroutines
	// and we don't have a way to wait for them to complete in this test
	// But at least we can verify the function runs without panicking
}
