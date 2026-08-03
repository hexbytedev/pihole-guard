// Package store manages the local hexwall SQLite database.
// Unlike the Pi-hole DB, this database is owned by the tool
// and persists trusted IPs and kill logs across restarts.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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

	// Prune windows: each table is deleted on a different schedule.
	pruneSNIWindow          = 7 * 24 * time.Hour  // SNI observations: operational state data; 7 days is enough for hand-inspection.
	pruneKilledAlertsWindow = 90 * 24 * time.Hour // Audit tables (killed_connections, zeek_alerts): rare events, forensically valuable.
	// fraud_checks and domain_checks are bounded by upsert-per-key and fraudCheckCacheWindow (6h);
	// they never grow beyond one row per IP/domain and are self-cleaning on read, so pruning is unnecessary.
)

const schema = `
CREATE TABLE IF NOT EXISTS allowed_ips (
    ip               TEXT    PRIMARY KEY,
    domain           TEXT    NOT NULL,
    first_approved   INTEGER NOT NULL,
    last_refreshed   INTEGER NOT NULL,
    last_established INTEGER
);

CREATE TABLE IF NOT EXISTS allowed_ip_domains (
    ip             TEXT    NOT NULL,
    domain         TEXT    NOT NULL,
    first_seen     INTEGER NOT NULL,
    last_refreshed INTEGER NOT NULL,
    PRIMARY KEY (ip, domain)
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
    ip          TEXT    NOT NULL,
    domain      TEXT    NOT NULL,
    local_port  TEXT    NOT NULL,
    outcome     TEXT    NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    times_seen  INTEGER NOT NULL,
    PRIMARY KEY (ip, domain, local_port)
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

CREATE TABLE IF NOT EXISTS ip_observations (
    ip          TEXT    NOT NULL,
    program     TEXT    NOT NULL,
    outcome     TEXT    NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    times_seen  INTEGER NOT NULL,
    PRIMARY KEY (ip, program)
);
`

// backfillAllowedIPDomains seeds the per-IP domain set from the older IP-level trust table.
// It runs on every startup: INSERT OR IGNORE makes it idempotent, and without it an upgraded
// install would treat every Zeek-observed SNI as a mismatch until the first cache refresh.
const backfillAllowedIPDomains = `
INSERT OR IGNORE INTO allowed_ip_domains (ip, domain, first_seen, last_refreshed)
SELECT ip, domain, first_approved, last_refreshed FROM allowed_ips WHERE TRIM(domain) <> '';
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

// SNIOutcome records which rung of the decision ladder classified a connection.
type SNIOutcome string

const (
	OutcomePolicyAllowed SNIOutcome = "policy-allowed"
	OutcomePolicyBlocked SNIOutcome = "policy-blocked"
	OutcomeIPDomainMatch SNIOutcome = "ip-domain-match"
	OutcomeUnknown       SNIOutcome = "unknown"
)

// Valid reports whether the outcome is one of the known values.
func (o SNIOutcome) Valid() bool {
	switch o {
	case OutcomePolicyAllowed, OutcomePolicyBlocked, OutcomeIPDomainMatch, OutcomeUnknown:
		return true
	}
	return false
}

// ParseSNIOutcome converts a string read from the database into a typed SNIOutcome.
// Rows written by older builds may contain unrecognized values; those parse to OutcomeUnknown with false.
func ParseSNIOutcome(s string) (SNIOutcome, bool) {
	o := SNIOutcome(s)
	if o.Valid() {
		return o, true
	}
	return OutcomeUnknown, false
}

// IPOutcome records how a connection was classified on the IP-only fallback path.
type IPOutcome string

const (
	OutcomeIPTrusted  IPOutcome = "ip-trusted"       // present and fresh in allowed_ips
	OutcomeIPReserved IPOutcome = "private-reserved" // deghost returned 403: private or reserved address
	OutcomeIPBlocked  IPOutcome = "deghost-blocked"  // deghost verdict said kill
	OutcomeIPUnknown  IPOutcome = "unknown"          // no verdict available or check disabled
)

// Valid reports whether the outcome is one of the known values.
func (o IPOutcome) Valid() bool {
	switch o {
	case OutcomeIPTrusted, OutcomeIPReserved, OutcomeIPBlocked, OutcomeIPUnknown:
		return true
	}
	return false
}

// ParseIPOutcome converts a string read from the database into a typed IPOutcome.
// Rows written by older builds may contain unrecognized values; those parse to OutcomeIPUnknown with false.
func ParseIPOutcome(s string) (IPOutcome, bool) {
	o := IPOutcome(s)
	if o.Valid() {
		return o, true
	}
	return OutcomeIPUnknown, false
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

// migrateSNITable detects the old event-log schema (identified by a "known" column)
// and drops it so the new state-table schema is applied by the CREATE TABLE IF NOT EXISTS.
// This is safe specifically because nothing in the codebase reads this table; a future reader
// must not assume this reasoning generalises to other tables.
func migrateSNITable(db *sql.DB) error {
	cols, err := db.Query(`PRAGMA table_info(sni_observations)`)
	if err != nil {
		return fmt.Errorf("query table info: %w", err)
	}
	defer cols.Close()

	hasOldSchema := false
	for cols.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := cols.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		if name == "known" {
			hasOldSchema = true
		}
	}
	if err := cols.Err(); err != nil {
		return fmt.Errorf("iterate table info: %w", err)
	}

	if !hasOldSchema {
		return nil
	}

	slog.Warn("dropping old sni_observations table (write-only audit data; no readers)", "reason", "schema migration to state-table format")
	if _, err := db.Exec(`DROP TABLE sni_observations`); err != nil {
		return fmt.Errorf("drop old sni_observations: %w", err)
	}
	return nil
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

	// Migration: detect and replace old sni_observations event-log schema with the new state table.
	// The old table used an autoincrement id + known INTEGER, which is structurally incompatible
	// with the new (ip, domain, local_port) primary key.  This is safe to drop because nothing in
	// the codebase reads this table — it was only ever written to and consulted by hand.
	if err := migrateSNITable(readWrite); err != nil {
		_ = readWrite.Close()
		return nil, fmt.Errorf("failed to migrate sni_observations: %w", err)
	}

	// Re-apply schema after migration so that any table dropped by migrateSNITable is recreated.
	if _, err := readWrite.Exec(schema); err != nil {
		_ = readWrite.Close()
		return nil, fmt.Errorf("failed to re-apply schema after migration: %w", err)
	}

	if _, err := readWrite.Exec(backfillAllowedIPDomains); err != nil {
		_ = readWrite.Close()
		return nil, fmt.Errorf("failed to backfill allowed ip domains: %w", err)
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

	return "file:" + (&url.URL{
		Path:     dbPath,
		RawQuery: query.Encode(),
	}).String()
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

// UpsertAllowedIPDomain inserts or refreshes one domain in the set of domains known for an IP.
// Unlike allowed_ips, which keeps a single representative domain per IP, this table records
// every domain observed for the IP so an SNI can be matched against that IP specifically.
// On conflict, it updates last_refreshed while preserving first_seen.
func (s *Store) UpsertAllowedIPDomain(ip, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	now := time.Now().Unix()

	_, err := s.readWrite.Exec(`
		INSERT INTO allowed_ip_domains (ip, domain, first_seen, last_refreshed)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip, domain) DO UPDATE SET
			last_refreshed = excluded.last_refreshed
	`, ip, domain, now, now)

	if err != nil {
		return fmt.Errorf("upsert allowed ip domain %s/%s: %w", ip, domain, err)
	}

	return nil
}

// DomainsForIP returns every domain on file for the IP that was refreshed within the trust window.
// It returns an empty slice when the IP has no fresh domains on record.
func (s *Store) DomainsForIP(ip string) ([]string, error) {
	cutoff := time.Now().Add(-refreshTrustWindow).Unix()

	rows, err := s.readOnly.Query(`
		SELECT domain
		FROM allowed_ip_domains
		WHERE ip = ?
		  AND last_refreshed >= ?
		ORDER BY domain
	`, ip, cutoff)
	if err != nil {
		return nil, fmt.Errorf("domains for ip %s: %w", ip, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	domains := []string{}
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("scan domain for ip %s: %w", ip, err)
		}

		domains = append(domains, domain)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate domains for ip %s: %w", ip, err)
	}

	return domains, nil
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

// LogSNIObservation records an SNI domain decision as a state-table upsert.
// On first sight it inserts the row; on subsequent observations it overwrites the outcome,
// updates last_seen, and increments times_seen while preserving first_seen.
func (s *Store) LogSNIObservation(ip, domain, localPort string, outcome SNIOutcome) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	now := time.Now().Unix()

	_, err := s.readWrite.Exec(`
		INSERT INTO sni_observations (ip, domain, local_port, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(ip, domain, local_port) DO UPDATE SET
			outcome    = excluded.outcome,
			last_seen  = excluded.last_seen,
			times_seen = sni_observations.times_seen + 1
	`, ip, domain, localPort, string(outcome), now, now)

	if err != nil {
		return fmt.Errorf("log sni observation %s: %w", ip, err)
	}

	return nil
}

// LogIPObservation records an IP-only fallback decision as a state-table upsert.
// On first sight it inserts the row; on subsequent observations it overwrites the outcome,
// updates last_seen, and increments times_seen while preserving first_seen.
func (s *Store) LogIPObservation(ip, program string, outcome IPOutcome) error {
	now := time.Now().Unix()

	_, err := s.readWrite.Exec(`
		INSERT INTO ip_observations (ip, program, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(ip, program) DO UPDATE SET
			outcome    = excluded.outcome,
			last_seen  = excluded.last_seen,
			times_seen = ip_observations.times_seen + 1
	`, ip, program, string(outcome), now, now)

	if err != nil {
		return fmt.Errorf("log ip observation %s: %w", ip, err)
	}

	return nil
}

// PruneResult reports how many rows were removed per table in a single Prune call.
type PruneResult struct {
	AllowedIPDomains  int64
	SNIObservations   int64
	IPObservations    int64
	KilledConnections int64
	ZeekAlerts        int64
}

// Prune removes stale rows from all pruneable tables.
// It returns the number of rows deleted per table so the caller can log a summary.
func (s *Store) Prune() (*PruneResult, error) {
	now := time.Now().Unix()
	result := &PruneResult{}

	// allowed_ip_domains: rows older than refreshTrustWindow are already excluded by
	// DomainsForIP and can never grant trust again. Safe to remove.
	r, err := s.readWrite.Exec(`DELETE FROM allowed_ip_domains WHERE last_refreshed < ?`, now-int64(refreshTrustWindow.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("prune allowed_ip_domains: %w", err)
	}
	result.AllowedIPDomains, _ = r.RowsAffected()

	// sni_observations: operational state data with a 7-day window.
	r, err = s.readWrite.Exec(`DELETE FROM sni_observations WHERE last_seen < ?`, now-int64(pruneSNIWindow.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("prune sni_observations: %w", err)
	}
	result.SNIObservations, _ = r.RowsAffected()

	// ip_observations: same 7-day window as sni_observations.
	r, err = s.readWrite.Exec(`DELETE FROM ip_observations WHERE last_seen < ?`, now-int64(pruneSNIWindow.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("prune ip_observations: %w", err)
	}
	result.IPObservations, _ = r.RowsAffected()

	// killed_connections and zeek_alerts: audit records of rare, potentially forensically
	// valuable events. 90-day window keeps a meaningful history without unbounded growth.
	r, err = s.readWrite.Exec(`DELETE FROM killed_connections WHERE killed_at < ?`, now-int64(pruneKilledAlertsWindow.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("prune killed_connections: %w", err)
	}
	result.KilledConnections, _ = r.RowsAffected()

	r, err = s.readWrite.Exec(`DELETE FROM zeek_alerts WHERE detected_at < ?`, now-int64(pruneKilledAlertsWindow.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("prune zeek_alerts: %w", err)
	}
	result.ZeekAlerts, _ = r.RowsAffected()

	return result, nil
}
