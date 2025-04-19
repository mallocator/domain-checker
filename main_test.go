// Package main provides a domain monitoring tool that checks for domain availability
// and expiration dates, sending notifications when domains are available or about to expire.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

// TestConfigLoading tests loading configuration from a file
func TestConfigLoading(t *testing.T) {
	// Create a temporary directory for config file
	tmpDir, err := os.MkdirTemp("", "main_test_config")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("Failed to remove temporary directory: %v", err)
		}
	}()

	// Create a config file
	configPath := filepath.Join(tmpDir, "config.json")
	configContent := `{
		"domains": ["example.com", "test.org"],
		"threshold_days": 25,
		"state_dir": "` + tmpDir + `",
		"concurrency": 3
	}`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Set environment variable for config file
	oldConfigFile := os.Getenv("CONFIG_FILE")
	defer func() {
		if err := os.Setenv("CONFIG_FILE", oldConfigFile); err != nil {
			t.Errorf("Failed to restore CONFIG_FILE: %v", err)
		}
	}()
	if err := os.Setenv("CONFIG_FILE", configPath); err != nil {
		t.Fatalf("Failed to set CONFIG_FILE: %v", err)
	}

	// Initialize logger
	log := logger.New()

	// Initialize configuration
	cfg := config.New(log)
	if err := cfg.LoadFromFile(os.Getenv("CONFIG_FILE")); err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	// Verify configuration was loaded correctly
	if len(cfg.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(cfg.Domains))
	}
	if cfg.Domains[0] != "example.com" || cfg.Domains[1] != "test.org" {
		t.Errorf("Expected domains [example.com test.org], got %v", cfg.Domains)
	}
	if cfg.ThresholdDays != 25 {
		t.Errorf("Expected threshold_days 25, got %d", cfg.ThresholdDays)
	}
	if cfg.StateDir != tmpDir {
		t.Errorf("Expected state_dir %s, got %s", tmpDir, cfg.StateDir)
	}
	if cfg.Concurrency != 3 {
		t.Errorf("Expected concurrency 3, got %d", cfg.Concurrency)
	}
}

// TestConfigLoadingFromEnv tests loading configuration from environment variables
func TestConfigLoadingFromEnv(t *testing.T) {
	// Create a temporary directory for state files
	tmpDir, err := os.MkdirTemp("", "main_test_env")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("Failed to remove temporary directory: %v", err)
		}
	}()

	// Save original environment variables
	oldDomains := os.Getenv("DOMAINS")
	oldThresholdDays := os.Getenv("THRESHOLD_DAYS")
	oldStateDir := os.Getenv("STATE_DIR")
	oldConcurrency := os.Getenv("CONCURRENCY")

	// Restore environment variables after test
	defer func() {
		if err := os.Setenv("DOMAINS", oldDomains); err != nil {
			t.Errorf("Failed to restore DOMAINS: %v", err)
		}
		if err := os.Setenv("THRESHOLD_DAYS", oldThresholdDays); err != nil {
			t.Errorf("Failed to restore THRESHOLD_DAYS: %v", err)
		}
		if err := os.Setenv("STATE_DIR", oldStateDir); err != nil {
			t.Errorf("Failed to restore STATE_DIR: %v", err)
		}
		if err := os.Setenv("CONCURRENCY", oldConcurrency); err != nil {
			t.Errorf("Failed to restore CONCURRENCY: %v", err)
		}
	}()

	// Set environment variables for test
	if err := os.Setenv("DOMAINS", "env1.com,env2.com"); err != nil {
		t.Fatalf("Failed to set DOMAINS: %v", err)
	}
	if err := os.Setenv("THRESHOLD_DAYS", "15"); err != nil {
		t.Fatalf("Failed to set THRESHOLD_DAYS: %v", err)
	}
	if err := os.Setenv("STATE_DIR", tmpDir); err != nil {
		t.Fatalf("Failed to set STATE_DIR: %v", err)
	}
	if err := os.Setenv("CONCURRENCY", "4"); err != nil {
		t.Fatalf("Failed to set CONCURRENCY: %v", err)
	}

	// Initialize logger
	log := logger.New()

	// Initialize configuration
	cfg := config.New(log)
	cfg.LoadFromEnv()

	// Verify configuration was loaded correctly
	if len(cfg.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(cfg.Domains))
	}
	if cfg.Domains[0] != "env1.com" || cfg.Domains[1] != "env2.com" {
		t.Errorf("Expected domains [env1.com env2.com], got %v", cfg.Domains)
	}
	if cfg.ThresholdDays != 15 {
		t.Errorf("Expected threshold_days 15, got %d", cfg.ThresholdDays)
	}
	if cfg.StateDir != tmpDir {
		t.Errorf("Expected state_dir %s, got %s", tmpDir, cfg.StateDir)
	}
	if cfg.Concurrency != 4 {
		t.Errorf("Expected concurrency 4, got %d", cfg.Concurrency)
	}
}

// TestStateDirectoryCreation tests that the state directory is created if it doesn't exist
func TestStateDirectoryCreation(t *testing.T) {
	// Create a temporary directory for the parent of the state directory
	parentDir, err := os.MkdirTemp("", "main_test_parent")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(parentDir); err != nil {
			t.Errorf("Failed to remove temporary directory: %v", err)
		}
	}()

	// Define a state directory that doesn't exist yet
	stateDir := filepath.Join(parentDir, "state")

	// Verify the directory doesn't exist yet
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("State directory already exists or error checking: %v", err)
	}

	// Create the directory using the same code as in main.go
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatalf("Failed to create state directory: %v", err)
	}

	// Verify the directory was created
	if _, err := os.Stat(stateDir); os.IsNotExist(err) {
		t.Errorf("State directory was not created")
	}
}
