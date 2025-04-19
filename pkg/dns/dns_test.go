package dns

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

func TestCreateDNSQuery(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)
	checker := New(cfg, log)

	tests := []struct {
		domain     string
		recordType uint16
		wantLen    int
	}{
		{"example.com", 6, 29}, // 12 (header) + 1 (len) + 7 (example) + 1 (len) + 3 (com) + 1 (null) + 2 (type) + 2 (class) = 29
		{"test.co.uk", 6, 28},  // 12 (header) + 1 (len) + 4 (test) + 1 (len) + 2 (co) + 1 (len) + 2 (uk) + 1 (null) + 2 (type) + 2 (class) = 28
		{"a.b.c", 6, 23},       // 12 (header) + 1 (len) + 1 (a) + 1 (len) + 1 (b) + 1 (len) + 1 (c) + 1 (null) + 2 (type) + 2 (class) = 23
	}

	for _, tc := range tests {
		query := checker.createDNSQuery(tc.domain, tc.recordType)

		// Check query length
		if len(query) != tc.wantLen {
			t.Errorf("createDNSQuery(%q, %d) returned query with length %d, want %d",
				tc.domain, tc.recordType, len(query), tc.wantLen)
		}

		// Check header fields
		if binary.BigEndian.Uint16(query[0:2]) != 1 { // ID
			t.Errorf("createDNSQuery(%q, %d) has incorrect ID", tc.domain, tc.recordType)
		}
		if binary.BigEndian.Uint16(query[2:4]) != 0x0100 { // Flags
			t.Errorf("createDNSQuery(%q, %d) has incorrect flags", tc.domain, tc.recordType)
		}
		if binary.BigEndian.Uint16(query[4:6]) != 1 { // QDCOUNT
			t.Errorf("createDNSQuery(%q, %d) has incorrect QDCOUNT", tc.domain, tc.recordType)
		}

		// Check record type
		typePos := len(query) - 4 // Type is 4 bytes from the end (2 for type, 2 for class)
		if binary.BigEndian.Uint16(query[typePos:typePos+2]) != tc.recordType {
			t.Errorf("createDNSQuery(%q, %d) has incorrect record type", tc.domain, tc.recordType)
		}

		// Check class (should be 1 for IN)
		if binary.BigEndian.Uint16(query[len(query)-2:]) != 1 {
			t.Errorf("createDNSQuery(%q, %d) has incorrect class", tc.domain, tc.recordType)
		}
	}
}

func TestParseSOAResponse(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)
	checker := New(cfg, log)

	// Test case 1: Response with SOA record (ancount > 0)
	responseWithSOA := []byte{
		0x00, 0x01, // ID
		0x81, 0x80, // Flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x01, // ANCOUNT (1 answer)
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// Rest of the response doesn't matter for this test
	}
	hasSOA, err := checker.parseSOAResponse(responseWithSOA)
	if err != nil {
		t.Errorf("parseSOAResponse() returned error: %v", err)
	}
	if !hasSOA {
		t.Errorf("parseSOAResponse() = %v, want true", hasSOA)
	}

	// Test case 2: Response without SOA record (ancount = 0)
	responseWithoutSOA := []byte{
		0x00, 0x01, // ID
		0x81, 0x80, // Flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT (0 answers)
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// Rest of the response doesn't matter for this test
	}
	hasSOA, err = checker.parseSOAResponse(responseWithoutSOA)
	if err != nil {
		t.Errorf("parseSOAResponse() returned error: %v", err)
	}
	if hasSOA {
		t.Errorf("parseSOAResponse() = %v, want false", hasSOA)
	}

	// Test case 3: Response too short
	responseTooShort := []byte{0x00, 0x01}
	_, err = checker.parseSOAResponse(responseTooShort)
	if err == nil {
		t.Errorf("parseSOAResponse() did not return error for too short response")
	}
}

func TestGetNameserver(t *testing.T) {
	log := logger.New()
	cfg := config.New(log)
	checker := New(cfg, log)

	// This test is more of an integration test since it depends on the system's
	// /etc/resolv.conf file. We'll just verify that it returns a valid IP.
	ip, err := checker.getNameserver()
	if err != nil {
		t.Errorf("getNameserver() returned error: %v", err)
	}
	if ip == nil {
		t.Errorf("getNameserver() returned nil IP")
	}

	// The IP should be either from resolv.conf or the default (8.8.8.8)
	if ip != nil {
		// Check if the IP is valid by comparing with Google's DNS or checking if it's a valid IP
		googleDNS := net.ParseIP("8.8.8.8")
		if !ip.Equal(googleDNS) && net.ParseIP(ip.String()) == nil {
			t.Errorf("getNameserver() returned invalid IP: %v", ip)
		}
	}
}
