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

func TestIsAppGeneratedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "app_file_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("failed to remove temp directory: %v", err)
		}
	}()

	// Create a valid app-generated file
	validFile := filepath.Join(tmpDir, "valid.json")
	validContent := `{"expiration":"2025-01-01T00:00:00Z","notified_expiry":false,"notified_available":true}`
	if err := os.WriteFile(validFile, []byte(validContent), 0644); err != nil {
		t.Fatalf("failed to write valid file: %v", err)
	}

	// Create an invalid JSON file
	invalidJSONFile := filepath.Join(tmpDir, "invalid_json.json")
	invalidJSONContent := `{"this is not valid JSON`
	if err := os.WriteFile(invalidJSONFile, []byte(invalidJSONContent), 0644); err != nil {
		t.Fatalf("failed to write invalid JSON file: %v", err)
	}

	// Create a non-JSON file
	nonJSONFile := filepath.Join(tmpDir, "non_json.txt")
	nonJSONContent := "This is not a JSON file"
	if err := os.WriteFile(nonJSONFile, []byte(nonJSONContent), 0644); err != nil {
		t.Fatalf("failed to write non-JSON file: %v", err)
	}

	// Test the isAppGeneratedFile function
	if !isAppGeneratedFile(validFile) {
		t.Errorf("isAppGeneratedFile(%q) = false, want true", validFile)
	}
	if isAppGeneratedFile(invalidJSONFile) {
		t.Errorf("isAppGeneratedFile(%q) = true, want false", invalidJSONFile)
	}
	if isAppGeneratedFile(nonJSONFile) {
		t.Errorf("isAppGeneratedFile(%q) = true, want false", nonJSONFile)
	}
}

func TestCleanupState(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "cleanup_test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("failed to remove temp directory: %v", err)
		}
	}()

	// Set the state directory to the temporary directory
	originalStateDir := cfg.StateDir
	cfg.StateDir = tmpDir
	defer func() {
		cfg.StateDir = originalStateDir
	}()

	// Set the domains for the test
	originalDomains := cfg.Domains
	cfg.Domains = []string{"example.com", "test.com"}
	defer func() {
		cfg.Domains = originalDomains
	}()

	// Create valid app-generated files for domains in the config
	validFile1 := filepath.Join(tmpDir, "example_com.json")
	validContent1 := `{"expiration":"2025-01-01T00:00:00Z","notified_expiry":false,"notified_available":true}`
	if err := os.WriteFile(validFile1, []byte(validContent1), 0644); err != nil {
		t.Fatalf("failed to write valid file: %v", err)
	}

	validFile2 := filepath.Join(tmpDir, "test_com.json")
	validContent2 := `{"expiration":"2025-01-01T00:00:00Z","notified_expiry":false,"notified_available":true}`
	if err := os.WriteFile(validFile2, []byte(validContent2), 0644); err != nil {
		t.Fatalf("failed to write valid file: %v", err)
	}

	// Create a valid app-generated file for a domain not in the config
	validFile3 := filepath.Join(tmpDir, "other_com.json")
	validContent3 := `{"expiration":"2025-01-01T00:00:00Z","notified_expiry":false,"notified_available":true}`
	if err := os.WriteFile(validFile3, []byte(validContent3), 0644); err != nil {
		t.Fatalf("failed to write valid file: %v", err)
	}

	// Create an invalid JSON file
	invalidJSONFile := filepath.Join(tmpDir, "invalid_json.json")
	invalidJSONContent := `{"this is not valid JSON`
	if err := os.WriteFile(invalidJSONFile, []byte(invalidJSONContent), 0644); err != nil {
		t.Fatalf("failed to write invalid JSON file: %v", err)
	}

	// Create a non-JSON file
	nonJSONFile := filepath.Join(tmpDir, "non_json.txt")
	nonJSONContent := "This is not a JSON file"
	if err := os.WriteFile(nonJSONFile, []byte(nonJSONContent), 0644); err != nil {
		t.Fatalf("failed to write non-JSON file: %v", err)
	}

	// Run the cleanupState function
	cleanupState()

	// Check that the files for domains in the config still exist
	if _, err := os.Stat(validFile1); os.IsNotExist(err) {
		t.Errorf("File %q was deleted, but it should still exist", validFile1)
	}
	if _, err := os.Stat(validFile2); os.IsNotExist(err) {
		t.Errorf("File %q was deleted, but it should still exist", validFile2)
	}

	// Check that the valid app-generated file for a domain not in the config was deleted
	if _, err := os.Stat(validFile3); !os.IsNotExist(err) {
		t.Errorf("File %q still exists, but it should have been deleted", validFile3)
	}

	// Check that the invalid JSON file and non-JSON file were not deleted
	if _, err := os.Stat(invalidJSONFile); os.IsNotExist(err) {
		t.Errorf("File %q was deleted, but it should still exist", invalidJSONFile)
	}
	if _, err := os.Stat(nonJSONFile); os.IsNotExist(err) {
		t.Errorf("File %q was deleted, but it should still exist", nonJSONFile)
	}
}
