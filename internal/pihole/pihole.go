// Package pihole reads query history from the Pi-hole FTL database.
// It exposes helpers for checking recent domains and building the trusted-IP cache.
package pihole

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Register the pure-Go SQLite driver used to read the Pi-hole FTL database.
	_ "modernc.org/sqlite"
)

// Config holds the Pi-hole database configuration.
type Config struct {
	DBPath        string
	GravityDBPath string // optional; derived from DBPath when empty
}

// Checker reads Pi-hole query history from the FTL database and policy lists from gravity.
type Checker struct {
	db        *sql.DB
	gravityDB *sql.DB
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

	// Open gravity.db for policy list lookups.
	gravityPath := config.GravityDBPath
	if gravityPath == "" {
		gravityPath = filepath.Join(filepath.Dir(config.DBPath), "gravity.db")
	}

	var gravityDB *sql.DB
	if err := openGravityDB(gravityPath, &gravityDB); err != nil {
		slog.Warn("pi-hole gravity database unavailable; policy checks disabled",
			"path", gravityPath, "err", err)
	}

	return &Checker{
		db:        db,
		gravityDB: gravityDB,
	}, nil
}

// openGravityDB opens the Pi-hole gravity database in read-only mode.
// On success it sets *out; on failure it returns an error but does not touch *out.
func openGravityDB(path string, out **sql.DB) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close access check for %s: %w", path, err)
	}

	dsn := "file:" + (&url.URL{Path: path, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open gravity-db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to connect to gravity-db: %w", err)
	}

	*out = db
	return nil
}

// Close closes both database connections.
func (c *Checker) Close() error {
	if c == nil {
		return nil
	}
	var errFTL error
	var errGravity error
	if c.db != nil {
		errFTL = c.db.Close()
	}
	if c.gravityDB != nil {
		errGravity = c.gravityDB.Close()
	}
	return errors.Join(errFTL, errGravity)
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

// IsAllowedByPolicy reports whether the domain currently appears in Pi-hole's allowlist.
func (c *Checker) IsAllowedByPolicy(domain string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}
	if c == nil || c.gravityDB == nil {
		return false, nil
	}

	var found int
	err := c.gravityDB.QueryRow(`
		SELECT 1 FROM vw_allowlist
		WHERE domain = ? COLLATE NOCASE
		LIMIT 1
	`, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("allowlist lookup failed: %w", err)
	}

	return true, nil
}

// IsBlockedByPolicy reports whether the domain currently matches a Pi-hole denylist or gravity entry.
func (c *Checker) IsBlockedByPolicy(domain string) (bool, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, nil
	}
	if c == nil || c.gravityDB == nil {
		return false, nil
	}

	var found int
	err := c.gravityDB.QueryRow(`
		SELECT 1 FROM vw_denylist
		WHERE domain = ? COLLATE NOCASE
		LIMIT 1
	`, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		// Not in denylist; check gravity.
	} else if err != nil {
		return false, fmt.Errorf("denylist lookup failed: %w", err)
	} else {
		return true, nil
	}

	err = c.gravityDB.QueryRow(`
		SELECT 1 FROM vw_gravity
		WHERE domain = ? COLLATE NOCASE
		LIMIT 1
	`, domain).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("gravity lookup failed: %w", err)
	}

	return true, nil
}

// PolicyCounts returns the number of entries in each Pi-hole policy view.
// The returned map is keyed by view name. Returns nil if gravity DB is unavailable.
func (c *Checker) PolicyCounts() (map[string]int64, error) {
	if c == nil || c.gravityDB == nil {
		return nil, nil
	}

	views := []string{"vw_allowlist", "vw_denylist", "vw_gravity", "vw_regex_allowlist", "vw_regex_denylist"}
	counts := make(map[string]int64, len(views))

	for _, view := range views {
		var count int64
		err := c.gravityDB.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, view)).Scan(&count)
		if err != nil {
			return nil, fmt.Errorf("count %s: %w", view, err)
		}
		counts[view] = count
	}

	return counts, nil
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

// DomainMatches reports whether an observed SNI domain corresponds to a known domain,
// treating a subdomain as a match for its parent in either direction.
//
// The direction is intentionally symmetric: Zeek reports the SNI exactly as sent on the wire
// (www.github.com) while the store holds whatever Pi-hole logged and the cache resolved
// (github.com), and either can be the more specific name.
//
// The match requires a label boundary, so github.com.evil.com does not match github.com:
// it does not end in ".github.com". A plain suffix test would have accepted it.
//
// A registrable-domain (eTLD+1) comparison via golang.org/x/net/publicsuffix would handle more
// edge cases -- notably unrelated names under a shared public suffix -- but it adds a third-party
// dependency for a marginal gain, so the label-boundary rule is the deliberate v1 tradeoff.
func DomainMatches(observed, known string) bool {
	observed = normalizeDomain(observed)
	known = normalizeDomain(known)

	if observed == "" || known == "" {
		return false
	}

	if observed == known {
		return true
	}

	return strings.HasSuffix(observed, "."+known) || strings.HasSuffix(known, "."+observed)
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}
