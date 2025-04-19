// Package dns provides DNS lookup functionality for the domain checker application
package dns

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/mallocator/domain-checker/pkg/config"
	"github.com/mallocator/domain-checker/pkg/logger"
)

// Checker handles DNS operations
type Checker struct {
	cfg *config.Config
	log *logger.Logger
}

// New creates a new DNS checker
func New(cfg *config.Config, log *logger.Logger) *Checker {
	return &Checker{
		cfg: cfg,
		log: log,
	}
}

// IsAvailable does DNS SOA lookup with context timeout
// Returns true if the domain is available (no SOA record found)
func (c *Checker) IsAvailable(domain string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()

	// Read DNS server from /etc/resolv.conf
	dnsServer, err := c.getNameserver()
	if err != nil {
		return false, fmt.Errorf("failed to read DNS config: %w", err)
	}

	// Create a DNS query for SOA record
	query := c.createDNSQuery(domain, 6) // 6 is the type code for SOA records

	// Send the query to the DNS server
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: dnsServer, Port: 53})
	if err != nil {
		return false, fmt.Errorf("failed to connect to DNS server: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			c.log.Warnf("Failed to close DNS connection: %v", err)
		}
	}()

	// Set deadline based on context
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			c.log.Warnf("Failed to set deadline for DNS connection: %v", err)
		}
	}

	// Send the query
	_, err = conn.Write(query)
	if err != nil {
		return false, fmt.Errorf("failed to send DNS query: %w", err)
	}

	// Receive the response
	response := make([]byte, 512) // Standard DNS message size
	n, err := conn.Read(response)
	if err != nil {
		return false, fmt.Errorf("failed to receive DNS response: %w", err)
	}

	// Parse the response to check for SOA records
	hasSOA, err := c.parseSOAResponse(response[:n])
	if err != nil {
		return false, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	// Domain is available if there's no SOA record
	return !hasSOA, nil
}

// getNameserver reads the first nameserver from /etc/resolv.conf
func (c *Checker) getNameserver() (net.IP, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		// If we can't open the file, default to Google's public DNS
		return net.ParseIP("8.8.8.8"), nil
	}
	defer func() {
		if err := file.Close(); err != nil {
			c.log.Warnf("Failed to close file: %v", err)
		}
	}()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Look for nameserver lines
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return net.ParseIP(fields[1]), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Default to Google's public DNS if no nameserver found
	return net.ParseIP("8.8.8.8"), nil
}

// createDNSQuery creates a minimal DNS query for the specified domain and record type
func (c *Checker) createDNSQuery(domain string, recordType uint16) []byte {
	// DNS header: ID, flags, counts
	query := []byte{
		0x00, 0x01, // ID: a random ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT: 1 question
		0x00, 0x00, // ANCOUNT: 0 answers
		0x00, 0x00, // NSCOUNT: 0 authority records
		0x00, 0x00, // ARCOUNT: 0 additional records
	}

	// Add the domain name in DNS format (length-prefixed labels)
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // Terminating zero length

	// Add QTYPE and QCLASS
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, recordType)
	query = append(query, typeBytes...)

	// QCLASS: IN (Internet)
	query = append(query, 0x00, 0x01)

	return query
}

// parseSOAResponse checks if the DNS response contains an SOA record
func (c *Checker) parseSOAResponse(response []byte) (bool, error) {
	if len(response) < 12 {
		return false, fmt.Errorf("response too short")
	}

	// Extract the number of answers from the response header
	ancount := binary.BigEndian.Uint16(response[6:8])

	// If there are any answers, assume there's an SOA record
	// This is a simplification - a full implementation would parse the answer section
	return ancount > 0, nil
}
