// Package logger provides a simple logging interface for the domain checker application
package logger

import (
	"fmt"
	"os"
	"strings"
)

// Logger is a simple logging interface
type Logger struct {
	debugEnabled bool
}

// New creates a new logger instance
func New() *Logger {
	return &Logger{
		debugEnabled: strings.ToLower(os.Getenv("DEBUG")) == "true",
	}
}

// Debugf logs debug messages when debug is enabled
func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.debugEnabled {
		if _, err := fmt.Fprintf(os.Stderr, "DEBUG: "+format+"\n", args...); err != nil {
			l.Errorf("Failed to write debug log: %v", err)
		}
	}
}

// Infof logs informational messages
func (l *Logger) Infof(format string, args ...interface{}) {
	if _, err := fmt.Fprintf(os.Stdout, "INFO: "+format+"\n", args...); err != nil {
		l.Errorf("Failed to write info log: %v", err)
	}
}

// Warnf logs warning messages
func (l *Logger) Warnf(format string, args ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, "WARN: "+format+"\n", args...); err != nil {
		l.Errorf("Failed to write warning log: %v", err)
	}
}

// Errorf logs error messages
func (l *Logger) Errorf(format string, args ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...); err != nil {
		// Can't use Errorf here to avoid infinite recursion
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Failed to write error log: %v\n", err)
	}
}

// Fatalf logs fatal messages and exits the program
func (l *Logger) Fatalf(format string, args ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...); err != nil {
		l.Errorf("Failed to write fatal log: %v", err)
	}
	os.Exit(1)
}

// SetDebug enables or disables debug logging
func (l *Logger) SetDebug(enabled bool) {
	l.debugEnabled = enabled
}