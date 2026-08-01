// Package store manages the local hexwall SQLite database.
// Unlike the Pi-hole DB, this database is owned by the tool
// and persists trusted IPs and kill logs across restarts.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	// Register the pure-Go SQLite driver used for the local hexwall database.
	_ "modernc.org/sqlite"
)

const (
	refreshTrustWindow     = time.Hour
	establishedTrustWindow = time.Minute
	fraudCheckCacheWindow  = 6 * time.Hour
	sqliteBusyTimeout      = 5 * time.Second
)

const schema = `
CREATE TABLE IF NOT EXISTS allowed_ips (
    ip               TEXT    PRIMARY KEY,
    domain           TEXT    NOT NULL,
    first_approved   INTEGER NOT NULL,
    last_refreshed   INTEGER NOT NULL,
    last_established INTEGER
);

CREATE TABLE IF NOT EXISTS killed_connections (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT    NOT NULL,
    pid       TEXT    NOT NULL,
    program   TEXT    NOT NULL,
    killed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS fraud_checks (
    ip         TEXT    PRIMARY KEY,
    should_kill INTEGER NOT NULL,
    checked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sni_observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,
    domain      TEXT    NOT NULL,
    local_port  TEXT    NOT NULL,
    known       INTEGER NOT NULL,
    observed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS zeek_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT    NOT NULL,
    dst_port     TEXT    NOT NULL,
    sni          TEXT    NOT NULL,
    blocked      INTEGER NOT NULL,
    confidence   TEXT    NOT NULL,
    detected_at  INTEGER NOT NULL,
    action_taken TEXT
);

CREATE TABLE IF NOT EXISTS domain_checks (
    domain       TEXT    PRIMARY KEY,
    should_block INTEGER NOT NULL,
    checked_at   INTEGER NOT NULL
);
`

// FraudCheckCacheEntry stores the cached kill decision for a prior fraud API lookup.
type FraudCheckCacheEntry struct {
	ShouldKill bool
	CheckedAt  int64
}

// DomainCheckCacheEntry stores the cached block decision for a prior domain reputation lookup.
type DomainCheckCacheEntry struct {
	ShouldBlock bool
	CheckedAt   int64
}

// ZeekAlertEntry stores a Zeek-derived alert that was persisted for audit.
type ZeekAlertEntry struct {
	ID          int64
	SrcIP       string
	DstIP       string
	DstPort     string
	SNI         string
	Blocked     bool
	Confidence  string
	DetectedAt  int64
	ActionTaken string
}

// Store wraps the local hexwall database.
type Store struct {
	readWrite *sql.DB
	readOnly  *sql.DB
}

// NewStore opens or creates the hexwall database at dbPath and applies the schema.
func NewStore(dbPath string) (*Store, error) {
	readWrite, err := sql.Open("sqlite", sqliteDSN(dbPath, "rwc"))
	if err != nil {
		return nil, fmt.Errorf("failed to open hexwall db: %w", err)
	}

	if err := configureConnection(readWrite, false); err != nil {
		_ = readWrite.Close()
		return nil, fmt.Errorf("failed to connect to hexwall db: %w", err)
	}

	if _, err := readWrite.Exec(schema); err != nil {
		_ = readWrite.Close()
		return nil, fmt.Errorf("failed to apply schema: %w", err)
	}

	readOnly, err := sql.Open("sqlite", sqliteDSN(dbPath, "ro"))
	if err != nil {
		_ = readWrite.Close()
		return nil, fmt.Errorf("failed to open hexwall db read-only connection: %w", err)
	}

	if err := configureConnection(readOnly, true); err != nil {
		_ = readOnly.Close()
		_ = readWrite.Close()
		return nil, fmt.Errorf("failed to connect to hexwall db read-only connection: %w", err)
	}

	return &Store{readWrite: readWrite, readOnly: readOnly}, nil
}

func sqliteDSN(dbPath, mode string) string {
	query := url.Values{}
	query.Set("mode", mode)

	return "file:" + (&url.URL{Path: dbPath, RawQuery: query.Encode()}).String()
}

func configureConnection(db *sql.DB, readOnly bool) error {
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	if _, err := db.Exec(fmt.Sprintf(`PRAGMA busy_timeout=%d;`, sqliteBusyTimeout/time.Millisecond)); err != nil {
		return fmt.Errorf("set busy_timeout: %w", err)
	}

	if readOnly {
		return nil
	}

	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return fmt.Errorf("set journal_mode WAL: %w", err)
	}

	return nil
}

// Close closes both database connections.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}

	var errReadWrite error
	var errReadOnly error

	if s.readWrite != nil {
		errReadWrite = s.readWrite.Close()
	}

	if s.readOnly != nil {
		errReadOnly = s.readOnly.Close()
	}

	return errors.Join(errReadWrite, errReadOnly)
}

// UpsertAllowedIP inserts or refreshes a trusted IP.
// On conflict, it updates the domain and last_refreshed while preserving first_approved and last_established.
func (s *Store) UpsertAllowedIP(ip, domain string) error {
	now := time.Now().Unix()

	_, err := s.readWrite.Exec(`
		INSERT INTO allowed_ips (ip, domain, first_approved, last_refreshed)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			domain        = excluded.domain,
			last_refreshed = excluded.last_refreshed
	`, ip, domain, now, now)

	if err != nil {
		return fmt.Errorf("upsert allowed ip %s: %w", ip, err)
	}

	return nil
}

// UpdateEstablished stamps the current time as last_established for an IP.
// The monitor calls it when somo confirms the connection is still active.
func (s *Store) UpdateEstablished(ip string) error {
	_, err := s.readWrite.Exec(`
		UPDATE allowed_ips SET last_established = ? WHERE ip = ?
	`, time.Now().Unix(), ip)

	if err != nil {
		return fmt.Errorf("update established %s: %w", ip, err)
	}

	return nil
}

// IsAllowed reports whether the IP is trusted based on a recent Pi-hole refresh or recent established-connection activity.
//
// It returns true if the IP is trusted. An IP is trusted when either:
//   - It was refreshed from Pi-hole's domain history within the last hour, OR
//   - somo confirmed it as an active established connection within the last 60 seconds
//     (keeps long-running connections alive even after their domain ages out)
func (s *Store) IsAllowed(ip string) (bool, error) {
	now := time.Now()
	refreshCutoff := now.Add(-refreshTrustWindow).Unix()
	establishedCutoff := now.Add(-establishedTrustWindow).Unix()

	var found int
	err := s.readOnly.QueryRow(`
		SELECT 1 FROM allowed_ips
		WHERE ip = ?
		  AND (last_refreshed   >= ?
		    OR last_established >= ?)
		LIMIT 1
	`, ip, refreshCutoff, establishedCutoff).Scan(&found)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("is allowed query for %s: %w", ip, err)
	}

	return true, nil
}

// GetRecentFraudCheck returns the cached fraud-check decision when it was recorded within the cache window.
func (s *Store) GetRecentFraudCheck(ip string) (*FraudCheckCacheEntry, error) {
	cutoff := time.Now().Add(-fraudCheckCacheWindow).Unix()

	var shouldKill int
	var checkedAt int64
	err := s.readOnly.QueryRow(`
		SELECT should_kill, checked_at
		FROM fraud_checks
		WHERE ip = ?
		  AND checked_at >= ?
		LIMIT 1
	`, ip, cutoff).Scan(&shouldKill, &checkedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("get recent fraud check for %s: %w", ip, err)
	}

	return &FraudCheckCacheEntry{
		ShouldKill: shouldKill != 0,
		CheckedAt:  checkedAt,
	}, nil
}

// UpsertFraudCheck stores the current fraud-check decision for an IP.
func (s *Store) UpsertFraudCheck(ip string, shouldKill bool) error {
	shouldKillInt := 0
	if shouldKill {
		shouldKillInt = 1
	}

	_, err := s.readWrite.Exec(`
		INSERT INTO fraud_checks (ip, should_kill, checked_at)
		VALUES (?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			should_kill = excluded.should_kill,
			checked_at = excluded.checked_at
	`, ip, shouldKillInt, time.Now().Unix())

	if err != nil {
		return fmt.Errorf("upsert fraud check %s: %w", ip, err)
	}

	return nil
}

// GetRecentDomainCheck returns the cached domain-check decision when it was recorded within the cache window.
func (s *Store) GetRecentDomainCheck(domain string) (*DomainCheckCacheEntry, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	cutoff := time.Now().Add(-fraudCheckCacheWindow).Unix()

	var shouldBlock int
	var checkedAt int64
	err := s.readOnly.QueryRow(`
		SELECT should_block, checked_at
		FROM domain_checks
		WHERE domain = ?
		  AND checked_at >= ?
		LIMIT 1
	`, domain, cutoff).Scan(&shouldBlock, &checkedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("get recent domain check for %s: %w", domain, err)
	}

	return &DomainCheckCacheEntry{
		ShouldBlock: shouldBlock != 0,
		CheckedAt:   checkedAt,
	}, nil
}

// UpsertDomainCheck stores the current domain-check decision.
func (s *Store) UpsertDomainCheck(domain string, shouldBlock bool) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	shouldBlockInt := 0
	if shouldBlock {
		shouldBlockInt = 1
	}

	_, err := s.readWrite.Exec(`
		INSERT INTO domain_checks (domain, should_block, checked_at)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			should_block = excluded.should_block,
			checked_at = excluded.checked_at
	`, domain, shouldBlockInt, time.Now().Unix())

	if err != nil {
		return fmt.Errorf("upsert domain check %s: %w", domain, err)
	}

	return nil
}

// LogKill records a killed connection in the audit log.
func (s *Store) LogKill(ip, pid, program string) error {
	_, err := s.readWrite.Exec(`
		INSERT INTO killed_connections (ip, pid, program, killed_at)
		VALUES (?, ?, ?, ?)
	`, ip, pid, program, time.Now().Unix())

	if err != nil {
		return fmt.Errorf("log kill %s: %w", ip, err)
	}

	return nil
}

// LogZeekAlert persists a Zeek-derived event for later review.
func (s *Store) LogZeekAlert(srcIP, dstIP, dstPort, sni string, blocked bool, confidence, actionTaken string) error {
	blockedInt := 0
	if blocked {
		blockedInt = 1
	}

	_, err := s.readWrite.Exec(`
		INSERT INTO zeek_alerts (src_ip, dst_ip, dst_port, sni, blocked, confidence, detected_at, action_taken)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, srcIP, dstIP, dstPort, sni, blockedInt, confidence, time.Now().Unix(), actionTaken)
	if err != nil {
		return fmt.Errorf("log zeek alert %s: %w", srcIP, err)
	}

	return nil
}

// RecentZeekAlert returns the most recent Zeek alert for the given source IP and SNI.
func (s *Store) RecentZeekAlert(srcIP, sni string) (*ZeekAlertEntry, error) {
	cutoff := time.Now().Add(-time.Hour).Unix()

	var id int64
	var dstIP string
	var dstPort string
	var blockedInt int
	var confidence string
	var detectedAt int64
	var actionTaken string
	err := s.readOnly.QueryRow(`
		SELECT id, dst_ip, dst_port, blocked, confidence, detected_at, action_taken
		FROM zeek_alerts
		WHERE src_ip = ?
		  AND sni = ?
		  AND detected_at >= ?
		ORDER BY id DESC
		LIMIT 1
	`, srcIP, sni, cutoff).Scan(&id, &dstIP, &dstPort, &blockedInt, &confidence, &detectedAt, &actionTaken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get recent zeek alert for %s: %w", srcIP, err)
	}

	return &ZeekAlertEntry{
		ID:          id,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		DstPort:     dstPort,
		SNI:         sni,
		Blocked:     blockedInt != 0,
		Confidence:  confidence,
		DetectedAt:  detectedAt,
		ActionTaken: actionTaken,
	}, nil
}

// LogSNIObservation records an SNI domain decision for auditability.
func (s *Store) LogSNIObservation(ip, domain, localPort string, known bool) error {
	knownInt := 0
	if known {
		knownInt = 1
	}

	_, err := s.readWrite.Exec(`
		INSERT INTO sni_observations (ip, domain, local_port, known, observed_at)
		VALUES (?, ?, ?, ?, ?)
	`, ip, domain, localPort, knownInt, time.Now().Unix())

	if err != nil {
		return fmt.Errorf("log sni observation %s: %w", ip, err)
	}

	return nil
}
