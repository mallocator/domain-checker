package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

func TestStateLoadSave(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)

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
	manager := New(cfg, log)

	domain := "test.com"
	stIn := DomainState{Expiration: time.Now(), NotifiedAvailable: true}
	manager.Save(domain, stIn)
	stOut := manager.Load(domain)

	if !stOut.NotifiedAvailable {
		t.Errorf("Load NotifiedAvailable = %v, want true", stOut.NotifiedAvailable)
	}
}

func TestIsAppGeneratedFile(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)
	manager := New(cfg, log)

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

	// Test the IsAppGeneratedFile function
	if !manager.IsAppGeneratedFile(validFile) {
		t.Errorf("IsAppGeneratedFile(%q) = false, want true", validFile)
	}
	if manager.IsAppGeneratedFile(invalidJSONFile) {
		t.Errorf("IsAppGeneratedFile(%q) = true, want false", invalidJSONFile)
	}
	if manager.IsAppGeneratedFile(nonJSONFile) {
		t.Errorf("IsAppGeneratedFile(%q) = true, want false", nonJSONFile)
	}
}

func TestCleanupState(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)

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
	cfg.StateDir = tmpDir

	// Set the domains for the test
	cfg.Domains = []string{"example.com", "test.com"}

	manager := New(cfg, log)

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

	// Run the Cleanup function
	manager.Cleanup()

	// Check that the files for domains in the config still exist
	if _, err := os.Stat(validFile1); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("File %q was deleted, but it should still exist", validFile1)
		} else {
			t.Errorf("Error checking file %q: %v", validFile1, err)
		}
	}
	if _, err := os.Stat(validFile2); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("File %q was deleted, but it should still exist", validFile2)
		} else {
			t.Errorf("Error checking file %q: %v", validFile2, err)
		}
	}

	// Check that the valid app-generated file for a domain not in the config was deleted
	if _, err := os.Stat(validFile3); err != nil {
		if !os.IsNotExist(err) {
			t.Errorf("Error checking file %q: %v", validFile3, err)
		}
	} else {
		t.Errorf("File %q still exists, but it should have been deleted", validFile3)
	}

	// Check that the invalid JSON file and non-JSON file were not deleted
	if _, err := os.Stat(invalidJSONFile); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("File %q was deleted, but it should still exist", invalidJSONFile)
		} else {
			t.Errorf("Error checking file %q: %v", invalidJSONFile, err)
		}
	}
	if _, err := os.Stat(nonJSONFile); err != nil {
		if os.IsNotExist(err) {
			t.Errorf("File %q was deleted, but it should still exist", nonJSONFile)
		} else {
			t.Errorf("Error checking file %q: %v", nonJSONFile, err)
		}
	}
}
