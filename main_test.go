package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseExpiration(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		err  bool
	}{
		{"2025-05-01T12:34:56Z", "2025-05-01T12:34:56Z", false},
		{"2025-05-01", "2025-05-01T00:00:00Z", false},
		{"invalid", "", true},
	}
	for _, tc := range tests {
		got, err := parseExpiration(tc.raw)
		if (err != nil) != tc.err {
			t.Errorf("parseExpiration(%q) err = %v, wantErr %v", tc.raw, err, tc.err)
			continue
		}
		if err == nil && got.Format(time.RFC3339) != tc.want {
			t.Errorf("parseExpiration(%q) = %s, want %s", tc.raw, got.Format(time.RFC3339), tc.want)
		}
	}
}

func TestStateLoadSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "state_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("failed to remove temp directory: %v", err)
		}
	}()
	cfg.StateDir = tmpDir
	domain := "test.com"
	stIn := DomainState{Expiration: time.Now(), NotifiedAvailable: true}
	saveState(domain, stIn)
	stOut := loadState(domain)
	if !stOut.NotifiedAvailable {
		t.Errorf("loadState NotifiedAvailable = %v, want true", stOut.NotifiedAvailable)
	}
}

func TestConfigFile(t *testing.T) {
	cfgFile := filepath.Join(os.TempDir(), "cfg.json")
	content := `{"threshold_days":3,"state_dir":"/tmp"}`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(cfgFile); err != nil {
			t.Errorf("failed to remove temp directory: %v", err)
		}
	}()
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	initDefaults()
	loadFileConfig(cfgFile)
	overrideWithEnv()
	if cfg.ThresholdDays != 3 || cfg.StateDir != "/tmp" {
		t.Errorf("Config loadFileConfig override error: %+v", cfg)
	}
}
