package whois

import (
	"testing"
	"time"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

func TestNew(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)

	checker := New(cfg, log)

	if checker == nil {
		t.Errorf("Expected New to return a non-nil Checker")
		return
	}

	if checker.cfg != cfg {
		t.Errorf("Expected checker.cfg to be %v, got %v", cfg, checker.cfg)
	}

	if checker.log != log {
		t.Errorf("Expected checker.log to be %v, got %v", log, checker.log)
	}
}

func TestParseExpiration(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)
	checker := New(cfg, log)

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
		got, err := checker.ParseExpiration(tc.raw)
		if (err != nil) != tc.err {
			t.Errorf("ParseExpiration(%q) err = %v, wantErr %v", tc.raw, err, tc.err)
			continue
		}
		if err == nil && got.Format(time.RFC3339) != tc.want {
			t.Errorf("ParseExpiration(%q) = %s, want %s", tc.raw, got.Format(time.RFC3339), tc.want)
		}
	}
}
