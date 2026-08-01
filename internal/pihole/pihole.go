// Package pihole reads query history from the Pi-hole FTL database.
// It exposes helpers for checking recent domains and building the trusted-IP cache.
package pihole

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	// Register the pure-Go SQLite driver used to read the Pi-hole FTL database.
	_ "modernc.org/sqlite"
)

// Config holds the Pi-hole database configuration.
type Config struct {
	DBPath string
}

// Checker reads Pi-hole query history from the FTL database.
type Checker struct {
	db *sql.DB
}

const domainLookback = time.Hour

// NewChecker opens a read-only Checker for the configured Pi-hole database.
func NewChecker(config *Config) (*Checker, error) {
	if config == nil {
		return nil, errors.New("missing pihole config")
	}

	if strings.TrimSpace(config.DBPath) == "" {
		return nil, errors.New("missing pihole database path")
	}

	// Check file access first so SQLite does not hide permission problems behind a generic error.
	file, err := os.Open(config.DBPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf(
				"permission denied reading %s; try running with sudo or: sudo chmod o+r %s",
				config.DBPath, config.DBPath,
			)
		}

		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pihole-FTL.db not found at %s", config.DBPath)
		}
		return nil, fmt.Errorf("cannot access %s: %w", config.DBPath, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close access check for %s: %w", config.DBPath, err)
	}

	dsn := "file:" + (&url.URL{Path: config.DBPath, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open pihole-db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to pihole-db: %w", err)
	}

	return &Checker{
		db: db,
	}, nil
}

// Close closes the Checker database connection.
func (c *Checker) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// IsDomainKnown reports whether domain appeared in Pi-hole query history within the last hour.
// Domains missing from that history bypassed Pi-hole DNS resolution and are treated as suspicious.
func (c *Checker) IsDomainKnown(domain string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}

	cutoff := time.Now().Add(-domainLookback).Unix()

	var found int
	err := c.db.QueryRow(`
		SELECT 1
		FROM queries
		WHERE timestamp >= ?
		  AND TRIM(domain) <> ''
		  AND domain = ? COLLATE NOCASE
		LIMIT 1
	`, cutoff, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("database query failed: %w", err)
	}

	return true, nil
}

// IsBlockedByPolicy reports whether the domain currently matches a Pi-hole policy entry.
func (c *Checker) IsBlockedByPolicy(domain string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}
	if c == nil || c.db == nil {
		return false, errors.New("pihole checker is not initialized")
	}

	var found int
	err := c.db.QueryRow(`
		SELECT 1
		FROM domainlist
		WHERE type IN (1, 2)
		  AND TRIM(domain) <> ''
		  AND domain = ? COLLATE NOCASE
		LIMIT 1
	`, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return false, nil
		}
		return false, fmt.Errorf("policy lookup failed: %w", err)
	}

	return true, nil
}

// DomainsSeenSince returns the distinct domains Pi-hole recorded since the given Unix timestamp.
func (c *Checker) DomainsSeenSince(since int64) ([]string, error) {
	rows, err := c.db.Query(`
		SELECT DISTINCT LOWER(TRIM(domain))
		FROM queries
		WHERE timestamp >= ?
		  AND domain IS NOT NULL
		  AND TRIM(domain) <> ''
		ORDER BY LOWER(TRIM(domain))
	`, since)
	if err != nil {
		return nil, fmt.Errorf("database query failed: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}

		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return domains, nil
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}
