package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallocator/domain-checker/pkg/logger"
)

func TestLoadFromFile(t *testing.T) {
	log := logger.New()

	// Create a temporary config file
	cfgFile := filepath.Join(os.TempDir(), "cfg.json")
	content := `{"threshold_days":3,"state_dir":"/tmp"}`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(cfgFile); err != nil {
			t.Errorf("failed to remove temp file: %v", err)
		}
	}()

	// Test loading from file
	cfg := New(log)
	if err := cfg.LoadFromFile(cfgFile); err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify the config was loaded correctly
	if cfg.ThresholdDays != 3 || cfg.StateDir != "/tmp" {
		t.Errorf("Config LoadFromFile error: got ThresholdDays=%d, StateDir=%s, want ThresholdDays=3, StateDir=/tmp",
			cfg.ThresholdDays, cfg.StateDir)
	}
}

func TestLoadFromEnv(t *testing.T) {
	log := logger.New()

	// Set environment variables
	if err := os.Setenv("THRESHOLD_DAYS", "5"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	if err := os.Setenv("STATE_DIR", "/var/data"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("THRESHOLD_DAYS"); err != nil {
			t.Errorf("Failed to unset environment variable: %v", err)
		}
		if err := os.Unsetenv("STATE_DIR"); err != nil {
			t.Errorf("Failed to unset environment variable: %v", err)
		}
	}()

	// Test loading from environment
	cfg := New(log)
	cfg.LoadFromEnv()

	// Verify the config was loaded correctly
	if cfg.ThresholdDays != 5 || cfg.StateDir != "/var/data" {
		t.Errorf("Config LoadFromEnv error: got ThresholdDays=%d, StateDir=%s, want ThresholdDays=5, StateDir=/var/data",
			cfg.ThresholdDays, cfg.StateDir)
	}
}

func TestLoadPriority(t *testing.T) {
	log := logger.New()

	// Create a temporary config file
	cfgFile := filepath.Join(os.TempDir(), "cfg.json")
	content := `{"threshold_days":3,"state_dir":"/tmp"}`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(cfgFile); err != nil {
			t.Errorf("failed to remove temp file: %v", err)
		}
	}()

	// Set environment variables
	if err := os.Setenv("THRESHOLD_DAYS", "5"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("THRESHOLD_DAYS"); err != nil {
			t.Errorf("Failed to unset environment variable: %v", err)
		}
	}()

	// Test loading from file then environment
	cfg := New(log)
	if err := cfg.LoadFromFile(cfgFile); err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	cfg.LoadFromEnv()

	// Verify the environment variables override the file config
	if cfg.ThresholdDays != 5 || cfg.StateDir != "/tmp" {
		t.Errorf("Config priority error: got ThresholdDays=%d, StateDir=%s, want ThresholdDays=5, StateDir=/tmp",
			cfg.ThresholdDays, cfg.StateDir)
	}
}
