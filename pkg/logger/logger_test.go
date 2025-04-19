package logger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func captureOutput(f func()) (string, string) {
	// Save original stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	// Create pipes for capturing output
	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		panic(fmt.Sprintf("Failed to create stdout pipe: %v", err))
	}
	rStderr, wStderr, err := os.Pipe()
	if err != nil {
		if err := rStdout.Close(); err != nil {
			fmt.Printf("Failed to close stdout pipe: %v\n", err)
		}
		panic(fmt.Sprintf("Failed to create stderr pipe: %v", err))
	}

	// Redirect stdout and stderr to the pipes
	os.Stdout = wStdout
	os.Stderr = wStderr

	// Execute the function that produces output
	f()

	// Close the write ends of the pipes to flush the buffers
	if err := wStdout.Close(); err != nil {
		panic(fmt.Sprintf("Failed to close stdout pipe: %v", err))
	}
	if err := wStderr.Close(); err != nil {
		panic(fmt.Sprintf("Failed to close stderr pipe: %v", err))
	}

	// Read the captured output
	var bufStdout, bufStderr bytes.Buffer
	if _, err := io.Copy(&bufStdout, rStdout); err != nil {
		panic(fmt.Sprintf("Failed to read from stdout pipe: %v", err))
	}
	if _, err := io.Copy(&bufStderr, rStderr); err != nil {
		panic(fmt.Sprintf("Failed to read from stderr pipe: %v", err))
	}

	// Close the read ends of the pipes
	if err := rStdout.Close(); err != nil {
		panic(fmt.Sprintf("Failed to close stdout reader: %v", err))
	}
	if err := rStderr.Close(); err != nil {
		panic(fmt.Sprintf("Failed to close stderr reader: %v", err))
	}

	// Restore original stdout and stderr
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	return bufStdout.String(), bufStderr.String()
}

func TestNew(t *testing.T) {
	// Test with DEBUG=true
	if err := os.Setenv("DEBUG", "true"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	logger := New()
	if !logger.debugEnabled {
		t.Errorf("Expected debugEnabled to be true when DEBUG=true")
	}

	// Test with DEBUG=false
	if err := os.Setenv("DEBUG", "false"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	logger = New()
	if logger.debugEnabled {
		t.Errorf("Expected debugEnabled to be false when DEBUG=false")
	}

	// Test with DEBUG not set
	if err := os.Unsetenv("DEBUG"); err != nil {
		t.Fatalf("Failed to unset environment variable: %v", err)
	}
	logger = New()
	if logger.debugEnabled {
		t.Errorf("Expected debugEnabled to be false when DEBUG is not set")
	}
}

func TestSetDebug(t *testing.T) {
	logger := New()

	// Test enabling debug
	logger.SetDebug(true)
	if !logger.debugEnabled {
		t.Errorf("Expected debugEnabled to be true after SetDebug(true)")
	}

	// Test disabling debug
	logger.SetDebug(false)
	if logger.debugEnabled {
		t.Errorf("Expected debugEnabled to be false after SetDebug(false)")
	}
}

func TestDebugf(t *testing.T) {
	logger := New()

	// Test with debug disabled
	logger.SetDebug(false)
	stdout, stderr := captureOutput(func() {
		logger.Debugf("Test debug message")
	})

	if stdout != "" || stderr != "" {
		t.Errorf("Expected no output with debug disabled, got stdout=%q, stderr=%q", stdout, stderr)
	}

	// Test with debug enabled
	logger.SetDebug(true)
	stdout, stderr = captureOutput(func() {
		logger.Debugf("Test debug message")
	})

	if stdout != "" {
		t.Errorf("Expected no stdout output, got %q", stdout)
	}
	if !strings.Contains(stderr, "DEBUG: Test debug message") {
		t.Errorf("Expected stderr to contain debug message, got %q", stderr)
	}
}

func TestInfof(t *testing.T) {
	logger := New()

	stdout, stderr := captureOutput(func() {
		logger.Infof("Test info message")
	})

	if !strings.Contains(stdout, "INFO: Test info message") {
		t.Errorf("Expected stdout to contain info message, got %q", stdout)
	}
	if stderr != "" {
		t.Errorf("Expected no stderr output, got %q", stderr)
	}
}

func TestWarnf(t *testing.T) {
	logger := New()

	stdout, stderr := captureOutput(func() {
		logger.Warnf("Test warning message")
	})

	if stdout != "" {
		t.Errorf("Expected no stdout output, got %q", stdout)
	}
	if !strings.Contains(stderr, "WARN: Test warning message") {
		t.Errorf("Expected stderr to contain warning message, got %q", stderr)
	}
}

func TestErrorf(t *testing.T) {
	logger := New()

	stdout, stderr := captureOutput(func() {
		logger.Errorf("Test error message")
	})

	if stdout != "" {
		t.Errorf("Expected no stdout output, got %q", stdout)
	}
	if !strings.Contains(stderr, "ERROR: Test error message") {
		t.Errorf("Expected stderr to contain error message, got %q", stderr)
	}
}

// Note: We can't fully test Fatalf because it calls os.Exit(1)
// which would terminate the test. We'll just test that it writes to stderr.
// This test will not actually call Fatalf to avoid terminating the test.
func TestFatalf(t *testing.T) {
	// Skip this test since we can't easily test os.Exit behavior
	t.Skip("Skipping TestFatalf because it would terminate the test process")

	// If we wanted to test this properly, we would need to:
	// 1. Create a separate test binary
	// 2. Run it as a subprocess
	// 3. Capture its output and exit code
	// This is beyond the scope of this simple test suite
}
