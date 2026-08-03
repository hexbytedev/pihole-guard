package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteDSNRelativePath(t *testing.T) {
	t.Parallel()

	dsn := sqliteDSN("./hexwall.db", "rwc")
	want := "file:./hexwall.db?mode=rwc"
	if dsn != want {
		t.Fatalf("sqliteDSN() = %q, want %q", dsn, want)
	}
}

func TestSQLiteDSNAbsolutePath(t *testing.T) {
	t.Parallel()

	dsn := sqliteDSN("/tmp/hexwall.db", "ro")
	want := "file:/tmp/hexwall.db?mode=ro"
	if dsn != want {
		t.Fatalf("sqliteDSN() = %q, want %q", dsn, want)
	}
}

func TestFraudCheckCacheRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	entry, err := hexwallStore.GetRecentFraudCheck("203.0.113.10")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() error = %v", err)
	}
	if entry != nil {
		t.Fatalf("GetRecentFraudCheck() = %#v, want nil before insert", entry)
	}

	if err := hexwallStore.UpsertFraudCheck("203.0.113.10", true); err != nil {
		t.Fatalf("UpsertFraudCheck() error = %v", err)
	}

	entry, err = hexwallStore.GetRecentFraudCheck("203.0.113.10")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() after insert error = %v", err)
	}
	if entry == nil {
		t.Fatal("GetRecentFraudCheck() = nil, want cached entry")
	}
	if !entry.ShouldKill {
		t.Fatal("GetRecentFraudCheck().ShouldKill = false, want true")
	}
	if entry.CheckedAt <= 0 {
		t.Fatalf("GetRecentFraudCheck().CheckedAt = %d, want positive unix timestamp", entry.CheckedAt)
	}
}

func TestFraudCheckCacheExpiresAfterWindow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	staleCheckedAt := time.Now().Add(-fraudCheckCacheWindow - time.Minute).Unix()
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO fraud_checks (ip, should_kill, checked_at)
		VALUES (?, ?, ?)
	`, "203.0.113.20", 0, staleCheckedAt); err != nil {
		t.Fatalf("insert stale fraud check error = %v", err)
	}

	entry, err := hexwallStore.GetRecentFraudCheck("203.0.113.20")
	if err != nil {
		t.Fatalf("GetRecentFraudCheck() error = %v", err)
	}
	if entry != nil {
		t.Fatalf("GetRecentFraudCheck() = %#v, want nil for stale entry", entry)
	}
}

func TestAllowedIPDomainsMultiplePerIP(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	for _, domain := range []string{"github.com", "example.com", "EXAMPLE.NET"} {
		if err := hexwallStore.UpsertAllowedIPDomain("203.0.113.30", domain); err != nil {
			t.Fatalf("UpsertAllowedIPDomain(%q) error = %v", domain, err)
		}
	}

	domains, err := hexwallStore.DomainsForIP("203.0.113.30")
	if err != nil {
		t.Fatalf("DomainsForIP() error = %v", err)
	}

	want := []string{"example.com", "example.net", "github.com"}
	if len(domains) != len(want) {
		t.Fatalf("DomainsForIP() = %v, want %v", domains, want)
	}
	for i, domain := range want {
		if domains[i] != domain {
			t.Fatalf("DomainsForIP()[%d] = %q, want %q", i, domains[i], domain)
		}
	}
}

func TestDomainsForIPUnknownIP(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if err := hexwallStore.UpsertAllowedIPDomain("203.0.113.30", "github.com"); err != nil {
		t.Fatalf("UpsertAllowedIPDomain() error = %v", err)
	}

	domains, err := hexwallStore.DomainsForIP("203.0.113.99")
	if err != nil {
		t.Fatalf("DomainsForIP() error = %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("DomainsForIP() = %v, want empty for unknown ip", domains)
	}
}

func TestDomainsForIPExcludesStaleEntries(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	staleRefreshed := time.Now().Add(-refreshTrustWindow - time.Minute).Unix()
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO allowed_ip_domains (ip, domain, first_seen, last_refreshed)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.40", "stale.example.com", staleRefreshed, staleRefreshed); err != nil {
		t.Fatalf("insert stale allowed ip domain error = %v", err)
	}

	if err := hexwallStore.UpsertAllowedIPDomain("203.0.113.40", "fresh.example.com"); err != nil {
		t.Fatalf("UpsertAllowedIPDomain() error = %v", err)
	}

	domains, err := hexwallStore.DomainsForIP("203.0.113.40")
	if err != nil {
		t.Fatalf("DomainsForIP() error = %v", err)
	}
	if len(domains) != 1 || domains[0] != "fresh.example.com" {
		t.Fatalf("DomainsForIP() = %v, want only the fresh domain", domains)
	}
}

func TestUpsertAllowedIPDomainRefreshesWithoutDuplicating(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	originalSeen := time.Now().Add(-30 * time.Minute).Unix()
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO allowed_ip_domains (ip, domain, first_seen, last_refreshed)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.50", "example.com", originalSeen, originalSeen); err != nil {
		t.Fatalf("insert allowed ip domain error = %v", err)
	}

	if err := hexwallStore.UpsertAllowedIPDomain("203.0.113.50", "example.com"); err != nil {
		t.Fatalf("UpsertAllowedIPDomain() error = %v", err)
	}

	var rowCount int
	var firstSeen int64
	var lastRefreshed int64
	if err := hexwallStore.readOnly.QueryRow(`
		SELECT COUNT(*), MIN(first_seen), MIN(last_refreshed)
		FROM allowed_ip_domains
		WHERE ip = ?
	`, "203.0.113.50").Scan(&rowCount, &firstSeen, &lastRefreshed); err != nil {
		t.Fatalf("query allowed ip domain error = %v", err)
	}

	if rowCount != 1 {
		t.Fatalf("row count = %d, want 1 after re-upsert", rowCount)
	}
	if firstSeen != originalSeen {
		t.Fatalf("first_seen = %d, want preserved value %d", firstSeen, originalSeen)
	}
	if lastRefreshed <= originalSeen {
		t.Fatalf("last_refreshed = %d, want a value newer than %d", lastRefreshed, originalSeen)
	}
}

func TestNewStoreBackfillsAllowedIPDomains(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	// UpsertAllowedIP writes only the IP-level record, mimicking a database written
	// before allowed_ip_domains existed.
	if err := hexwallStore.UpsertAllowedIP("203.0.113.60", "example.com"); err != nil {
		t.Fatalf("UpsertAllowedIP() error = %v", err)
	}
	if err := hexwallStore.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() reopen error = %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	domains, err := reopened.DomainsForIP("203.0.113.60")
	if err != nil {
		t.Fatalf("DomainsForIP() error = %v", err)
	}
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Fatalf("DomainsForIP() = %v, want [example.com] from backfill", domains)
	}
}

func TestDomainCheckCacheRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	entry, err := hexwallStore.GetRecentDomainCheck("evil.example.com")
	if err != nil {
		t.Fatalf("GetRecentDomainCheck() error = %v", err)
	}
	if entry != nil {
		t.Fatalf("GetRecentDomainCheck() = %#v, want nil before insert", entry)
	}

	if err := hexwallStore.UpsertDomainCheck("evil.example.com", true); err != nil {
		t.Fatalf("UpsertDomainCheck() error = %v", err)
	}

	entry, err = hexwallStore.GetRecentDomainCheck("evil.example.com")
	if err != nil {
		t.Fatalf("GetRecentDomainCheck() after insert error = %v", err)
	}
	if entry == nil {
		t.Fatal("GetRecentDomainCheck() = nil, want cached entry")
	}
	if !entry.ShouldBlock {
		t.Fatal("GetRecentDomainCheck().ShouldBlock = false, want true")
	}
	if entry.CheckedAt <= 0 {
		t.Fatalf("GetRecentDomainCheck().CheckedAt = %d, want positive unix timestamp", entry.CheckedAt)
	}
}

func TestDomainCheckCacheNormalizedKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if err := hexwallStore.UpsertDomainCheck("EXAMPLE.COM", false); err != nil {
		t.Fatalf("UpsertDomainCheck() error = %v", err)
	}

	entry, err := hexwallStore.GetRecentDomainCheck("  example.com  ")
	if err != nil {
		t.Fatalf("GetRecentDomainCheck() error = %v", err)
	}
	if entry == nil {
		t.Fatal("GetRecentDomainCheck() = nil, normalized key lookup should match")
	}
	if entry.ShouldBlock {
		t.Fatal("GetRecentDomainCheck().ShouldBlock = true, want false")
	}
}

func TestDomainCheckCacheExpiresAfterWindow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	staleCheckedAt := time.Now().Add(-fraudCheckCacheWindow - time.Minute).Unix()
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO domain_checks (domain, should_block, checked_at)
		VALUES (?, ?, ?)
	`, "stale.example.com", 1, staleCheckedAt); err != nil {
		t.Fatalf("insert stale domain check error = %v", err)
	}

	entry, err := hexwallStore.GetRecentDomainCheck("stale.example.com")
	if err != nil {
		t.Fatalf("GetRecentDomainCheck() error = %v", err)
	}
	if entry != nil {
		t.Fatalf("GetRecentDomainCheck() = %#v, want nil for stale entry", entry)
	}
}

func TestParseSNIOutcomeValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  SNIOutcome
	}{
		{"policy-allowed", OutcomePolicyAllowed},
		{"policy-blocked", OutcomePolicyBlocked},
		{"ip-domain-match", OutcomeIPDomainMatch},
		{"unknown", OutcomeUnknown},
	}

	for _, tt := range tests {
		got, ok := ParseSNIOutcome(tt.input)
		if !ok {
			t.Errorf("ParseSNIOutcome(%q) ok = false, want true", tt.input)
		}
		if got != tt.want {
			t.Errorf("ParseSNIOutcome(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseSNIOutcomeInvalid(t *testing.T) {
	t.Parallel()

	tests := []string{"", "bogus", "true", "false", "1", "0"}
	for _, input := range tests {
		got, ok := ParseSNIOutcome(input)
		if ok {
			t.Errorf("ParseSNIOutcome(%q) ok = true, want false", input)
		}
		if got != OutcomeUnknown {
			t.Errorf("ParseSNIOutcome(%q) = %q, want %q", input, got, OutcomeUnknown)
		}
	}
}

func TestSNIOutcomeValid(t *testing.T) {
	t.Parallel()

	valid := []SNIOutcome{OutcomePolicyAllowed, OutcomePolicyBlocked, OutcomeIPDomainMatch, OutcomeUnknown}
	for _, o := range valid {
		if !o.Valid() {
			t.Errorf("SNIOutcome(%q).Valid() = false, want true", o)
		}
	}

	invalid := []SNIOutcome{"bogus", "", "true"}
	for _, o := range invalid {
		if o.Valid() {
			t.Errorf("SNIOutcome(%q).Valid() = true, want false", o)
		}
	}
}

func TestLogSNIObservationInsertAndUpsert(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	// First insert.
	if err := hexwallStore.LogSNIObservation("203.0.113.10", "example.com", "443", OutcomePolicyAllowed); err != nil {
		t.Fatalf("LogSNIObservation() error = %v", err)
	}

	var timesSeen int
	var firstSeen, lastSeen int64
	var outcome string
	err = hexwallStore.readOnly.QueryRow(`
		SELECT times_seen, first_seen, last_seen, outcome
		FROM sni_observations
		WHERE ip = ? AND domain = ? AND local_port = ?
	`, "203.0.113.10", "example.com", "443").Scan(&timesSeen, &firstSeen, &lastSeen, &outcome)
	if err != nil {
		t.Fatalf("query sni_observations error = %v", err)
	}
	if timesSeen != 1 {
		t.Fatalf("times_seen = %d, want 1 after first insert", timesSeen)
	}
	if firstSeen <= 0 {
		t.Fatalf("first_seen = %d, want positive unix timestamp", firstSeen)
	}
	if lastSeen != firstSeen {
		t.Fatalf("last_seen = %d, want equal to first_seen on first insert, got %d", lastSeen, firstSeen)
	}
	if outcome != "policy-allowed" {
		t.Fatalf("outcome = %q, want %q", outcome, "policy-allowed")
	}

	// Second insert with different outcome — should upsert.
	if err := hexwallStore.LogSNIObservation("203.0.113.10", "example.com", "443", OutcomeIPDomainMatch); err != nil {
		t.Fatalf("LogSNIObservation() upsert error = %v", err)
	}

	err = hexwallStore.readOnly.QueryRow(`
		SELECT times_seen, first_seen, last_seen, outcome
		FROM sni_observations
		WHERE ip = ? AND domain = ? AND local_port = ?
	`, "203.0.113.10", "example.com", "443").Scan(&timesSeen, &firstSeen, &lastSeen, &outcome)
	if err != nil {
		t.Fatalf("query sni_observations after upsert error = %v", err)
	}
	if timesSeen != 2 {
		t.Fatalf("times_seen = %d, want 2 after upsert", timesSeen)
	}
	if outcome != "ip-domain-match" {
		t.Fatalf("outcome = %q, want %q after upsert", outcome, "ip-domain-match")
	}
	if lastSeen < firstSeen {
		t.Fatalf("last_seen = %d should not be older than first_seen = %d", lastSeen, firstSeen)
	}

	// Third insert — times_seen should be 3.
	if err := hexwallStore.LogSNIObservation("203.0.113.10", "example.com", "443", OutcomePolicyBlocked); err != nil {
		t.Fatalf("LogSNIObservation() third insert error = %v", err)
	}

	err = hexwallStore.readOnly.QueryRow(`
		SELECT times_seen, outcome
		FROM sni_observations
		WHERE ip = ? AND domain = ? AND local_port = ?
	`, "203.0.113.10", "example.com", "443").Scan(&timesSeen, &outcome)
	if err != nil {
		t.Fatalf("query sni_observations after third insert error = %v", err)
	}
	if timesSeen != 3 {
		t.Fatalf("times_seen = %d, want 3 after third insert", timesSeen)
	}
	if outcome != "policy-blocked" {
		t.Fatalf("outcome = %q, want %q after third insert", outcome, "policy-blocked")
	}
}

func TestLogSNIObservationNormalizesDomain(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if err := hexwallStore.LogSNIObservation("203.0.113.10", "  EXAMPLE.COM  ", "443", OutcomePolicyAllowed); err != nil {
		t.Fatalf("LogSNIObservation() error = %v", err)
	}

	// Lookup by the normalized form.
	var outcome string
	err = hexwallStore.readOnly.QueryRow(`
		SELECT outcome FROM sni_observations
		WHERE ip = ? AND domain = ? AND local_port = ?
	`, "203.0.113.10", "example.com", "443").Scan(&outcome)
	if err != nil {
		t.Fatalf("query sni_observations for normalized domain error = %v", err)
	}
	if outcome != "policy-allowed" {
		t.Fatalf("outcome = %q, want %q", outcome, "policy-allowed")
	}
}

func TestNewStoreMigratesOldSNITable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	// Create a store with the old schema manually.
	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	// Drop the new table and recreate with the old schema.
	if _, err := hexwallStore.readWrite.Exec(`DROP TABLE sni_observations`); err != nil {
		t.Fatalf("drop sni_observations error = %v", err)
	}
	if _, err := hexwallStore.readWrite.Exec(`
		CREATE TABLE sni_observations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL, domain TEXT NOT NULL, local_port TEXT NOT NULL,
			known INTEGER NOT NULL, observed_at INTEGER NOT NULL
		)
	`); err != nil {
		t.Fatalf("create old sni_observations error = %v", err)
	}
	// Insert a row in the old format.
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO sni_observations (ip, domain, local_port, known, observed_at)
		VALUES (?, ?, ?, ?, ?)
	`, "203.0.113.20", "old.example.com", "443", 1, time.Now().Unix()); err != nil {
		t.Fatalf("insert old sni_observations error = %v", err)
	}
	if err := hexwallStore.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Reopen — migration should drop the old table and create the new one.
	reopened, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() reopen error = %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	// The old row should be gone.
	var count int
	err = reopened.readOnly.QueryRow(`SELECT COUNT(*) FROM sni_observations`).Scan(&count)
	if err != nil {
		t.Fatalf("query sni_observations count error = %v", err)
	}
	if count != 0 {
		t.Fatalf("row count = %d, want 0 after migration dropped old table", count)
	}

	// The new schema should work.
	if err := reopened.LogSNIObservation("203.0.113.20", "new.example.com", "443", OutcomePolicyAllowed); err != nil {
		t.Fatalf("LogSNIObservation() after migration error = %v", err)
	}

	err = reopened.readOnly.QueryRow(`SELECT COUNT(*) FROM sni_observations`).Scan(&count)
	if err != nil {
		t.Fatalf("query sni_observations count after insert error = %v", err)
	}
	if count != 1 {
		t.Fatalf("row count = %d, want 1 after insert with new schema", count)
	}
}

func TestPruneRemovesStaleRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	now := time.Now().Unix()

	// Insert stale allowed_ip_domains (older than refreshTrustWindow).
	staleRefreshed := now - int64(refreshTrustWindow.Seconds()) - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO allowed_ip_domains (ip, domain, first_seen, last_refreshed)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.30", "stale.example.com", staleRefreshed, staleRefreshed); err != nil {
		t.Fatalf("insert stale allowed_ip_domains error = %v", err)
	}

	// Insert fresh allowed_ip_domains.
	freshRefreshed := now - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO allowed_ip_domains (ip, domain, first_seen, last_refreshed)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.30", "fresh.example.com", freshRefreshed, freshRefreshed); err != nil {
		t.Fatalf("insert fresh allowed_ip_domains error = %v", err)
	}

	// Insert stale sni_observations (older than 7 days).
	staleSNI := now - int64(pruneSNIWindow.Seconds()) - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO sni_observations (ip, domain, local_port, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "203.0.113.30", "stale.example.com", "443", "unknown", staleSNI, staleSNI, 5); err != nil {
		t.Fatalf("insert stale sni_observations error = %v", err)
	}

	// Insert fresh sni_observations.
	freshSNI := now - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO sni_observations (ip, domain, local_port, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "203.0.113.30", "fresh.example.com", "443", "unknown", freshSNI, freshSNI, 1); err != nil {
		t.Fatalf("insert fresh sni_observations error = %v", err)
	}

	// Insert stale killed_connections (older than 90 days).
	staleKill := now - int64(pruneKilledAlertsWindow.Seconds()) - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO killed_connections (ip, pid, program, killed_at)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.30", "1234", "curl", staleKill); err != nil {
		t.Fatalf("insert stale killed_connections error = %v", err)
	}

	// Insert fresh killed_connections.
	freshKill := now - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO killed_connections (ip, pid, program, killed_at)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.30", "5678", "wget", freshKill); err != nil {
		t.Fatalf("insert fresh killed_connections error = %v", err)
	}

	// Insert stale zeek_alerts.
	staleZeek := now - int64(pruneKilledAlertsWindow.Seconds()) - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO zeek_alerts (src_ip, dst_ip, dst_port, sni, blocked, confidence, detected_at, action_taken)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "10.0.0.1", "203.0.113.30", "443", "old.example.com", 0, "low", staleZeek, "logged"); err != nil {
		t.Fatalf("insert stale zeek_alerts error = %v", err)
	}

	// Insert fresh zeek_alerts.
	freshZeek := now - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO zeek_alerts (src_ip, dst_ip, dst_port, sni, blocked, confidence, detected_at, action_taken)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "10.0.0.2", "203.0.113.30", "443", "new.example.com", 1, "high", freshZeek, "logged"); err != nil {
		t.Fatalf("insert fresh zeek_alerts error = %v", err)
	}

	// Run prune.
	result, err := hexwallStore.Prune()
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	if result.AllowedIPDomains != 1 {
		t.Fatalf("Prune().AllowedIPDomains = %d, want 1", result.AllowedIPDomains)
	}
	if result.SNIObservations != 1 {
		t.Fatalf("Prune().SNIObservations = %d, want 1", result.SNIObservations)
	}
	if result.KilledConnections != 1 {
		t.Fatalf("Prune().KilledConnections = %d, want 1", result.KilledConnections)
	}
	if result.ZeekAlerts != 1 {
		t.Fatalf("Prune().ZeekAlerts = %d, want 1", result.ZeekAlerts)
	}

	// Verify fresh rows remain.
	var count int
	if err := hexwallStore.readOnly.QueryRow(`SELECT COUNT(*) FROM allowed_ip_domains`).Scan(&count); err != nil {
		t.Fatalf("query allowed_ip_domains count error = %v", err)
	}
	if count != 1 {
		t.Fatalf("allowed_ip_domains count = %d, want 1 fresh row remaining", count)
	}

	if err := hexwallStore.readOnly.QueryRow(`SELECT COUNT(*) FROM sni_observations`).Scan(&count); err != nil {
		t.Fatalf("query sni_observations count error = %v", err)
	}
	if count != 1 {
		t.Fatalf("sni_observations count = %d, want 1 fresh row remaining", count)
	}

	if err := hexwallStore.readOnly.QueryRow(`SELECT COUNT(*) FROM killed_connections`).Scan(&count); err != nil {
		t.Fatalf("query killed_connections count error = %v", err)
	}
	if count != 1 {
		t.Fatalf("killed_connections count = %d, want 1 fresh row remaining", count)
	}

	if err := hexwallStore.readOnly.QueryRow(`SELECT COUNT(*) FROM zeek_alerts`).Scan(&count); err != nil {
		t.Fatalf("query zeek_alerts count error = %v", err)
	}
	if count != 1 {
		t.Fatalf("zeek_alerts count = %d, want 1 fresh row remaining", count)
	}
}

func TestPruneNoopWhenNothingExpired(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	now := time.Now().Unix()

	// Insert fresh rows in all pruneable tables.
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO allowed_ip_domains (ip, domain, first_seen, last_refreshed)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.40", "fresh.example.com", now, now); err != nil {
		t.Fatalf("insert fresh allowed_ip_domains error = %v", err)
	}
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO sni_observations (ip, domain, local_port, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, "203.0.113.40", "fresh.example.com", "443", "unknown", now, now, 1); err != nil {
		t.Fatalf("insert fresh sni_observations error = %v", err)
	}
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO killed_connections (ip, pid, program, killed_at)
		VALUES (?, ?, ?, ?)
	`, "203.0.113.40", "1234", "curl", now); err != nil {
		t.Fatalf("insert fresh killed_connections error = %v", err)
	}
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO zeek_alerts (src_ip, dst_ip, dst_port, sni, blocked, confidence, detected_at, action_taken)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "10.0.0.1", "203.0.113.40", "443", "fresh.example.com", 0, "low", now, "logged"); err != nil {
		t.Fatalf("insert fresh zeek_alerts error = %v", err)
	}
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO ip_observations (ip, program, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "203.0.113.40", "curl", "unknown", now, now, 1); err != nil {
		t.Fatalf("insert fresh ip_observations error = %v", err)
	}

	result, err := hexwallStore.Prune()
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	total := result.AllowedIPDomains + result.SNIObservations + result.IPObservations + result.KilledConnections + result.ZeekAlerts
	if total != 0 {
		t.Fatalf("Prune() deleted %d total rows, want 0 when nothing is expired", total)
	}
}

func TestParseIPOutcomeValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  IPOutcome
	}{
		{"ip-trusted", OutcomeIPTrusted},
		{"private-reserved", OutcomeIPReserved},
		{"deghost-blocked", OutcomeIPBlocked},
		{"unknown", OutcomeIPUnknown},
	}

	for _, tt := range tests {
		got, ok := ParseIPOutcome(tt.input)
		if !ok {
			t.Errorf("ParseIPOutcome(%q) ok = false, want true", tt.input)
		}
		if got != tt.want {
			t.Errorf("ParseIPOutcome(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseIPOutcomeInvalid(t *testing.T) {
	t.Parallel()

	tests := []string{"", "bogus", "true", "false", "1", "0"}
	for _, input := range tests {
		got, ok := ParseIPOutcome(input)
		if ok {
			t.Errorf("ParseIPOutcome(%q) ok = true, want false", input)
		}
		if got != OutcomeIPUnknown {
			t.Errorf("ParseIPOutcome(%q) = %q, want %q", input, got, OutcomeIPUnknown)
		}
	}
}

func TestIPOutcomeValid(t *testing.T) {
	t.Parallel()

	valid := []IPOutcome{OutcomeIPTrusted, OutcomeIPReserved, OutcomeIPBlocked, OutcomeIPUnknown}
	for _, o := range valid {
		if !o.Valid() {
			t.Errorf("IPOutcome(%q).Valid() = false, want true", o)
		}
	}

	invalid := []IPOutcome{"bogus", "", "true"}
	for _, o := range invalid {
		if o.Valid() {
			t.Errorf("IPOutcome(%q).Valid() = true, want false", o)
		}
	}
}

func TestLogIPObservationInsertAndUpsert(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	// First insert.
	if err := hexwallStore.LogIPObservation("203.0.113.10", "curl", OutcomeIPTrusted); err != nil {
		t.Fatalf("LogIPObservation() error = %v", err)
	}

	var timesSeen int
	var firstSeen, lastSeen int64
	var outcome string
	err = hexwallStore.readOnly.QueryRow(`
		SELECT times_seen, first_seen, last_seen, outcome
		FROM ip_observations
		WHERE ip = ? AND program = ?
	`, "203.0.113.10", "curl").Scan(&timesSeen, &firstSeen, &lastSeen, &outcome)
	if err != nil {
		t.Fatalf("query ip_observations error = %v", err)
	}
	if timesSeen != 1 {
		t.Fatalf("times_seen = %d, want 1 after first insert", timesSeen)
	}
	if firstSeen <= 0 {
		t.Fatalf("first_seen = %d, want positive unix timestamp", firstSeen)
	}
	if lastSeen != firstSeen {
		t.Fatalf("last_seen = %d, want equal to first_seen on first insert, got %d", lastSeen, firstSeen)
	}
	if outcome != "ip-trusted" {
		t.Fatalf("outcome = %q, want %q", outcome, "ip-trusted")
	}

	// Second insert with different outcome — should upsert.
	if err := hexwallStore.LogIPObservation("203.0.113.10", "curl", OutcomeIPBlocked); err != nil {
		t.Fatalf("LogIPObservation() upsert error = %v", err)
	}

	err = hexwallStore.readOnly.QueryRow(`
		SELECT times_seen, first_seen, last_seen, outcome
		FROM ip_observations
		WHERE ip = ? AND program = ?
	`, "203.0.113.10", "curl").Scan(&timesSeen, &firstSeen, &lastSeen, &outcome)
	if err != nil {
		t.Fatalf("query ip_observations after upsert error = %v", err)
	}
	if timesSeen != 2 {
		t.Fatalf("times_seen = %d, want 2 after upsert", timesSeen)
	}
	if outcome != "deghost-blocked" {
		t.Fatalf("outcome = %q, want %q after upsert", outcome, "deghost-blocked")
	}
	if lastSeen < firstSeen {
		t.Fatalf("last_seen = %d should not be older than first_seen = %d", lastSeen, firstSeen)
	}

	// Third insert — times_seen should be 3.
	if err := hexwallStore.LogIPObservation("203.0.113.10", "curl", OutcomeIPReserved); err != nil {
		t.Fatalf("LogIPObservation() third insert error = %v", err)
	}

	err = hexwallStore.readOnly.QueryRow(`
		SELECT times_seen, outcome
		FROM ip_observations
		WHERE ip = ? AND program = ?
	`, "203.0.113.10", "curl").Scan(&timesSeen, &outcome)
	if err != nil {
		t.Fatalf("query ip_observations after third insert error = %v", err)
	}
	if timesSeen != 3 {
		t.Fatalf("times_seen = %d, want 3 after third insert", timesSeen)
	}
	if outcome != "private-reserved" {
		t.Fatalf("outcome = %q, want %q after third insert", outcome, "private-reserved")
	}
}

func TestLogIPObservationDifferentPrograms(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	// Same IP, different programs — should create separate rows.
	if err := hexwallStore.LogIPObservation("203.0.113.20", "curl", OutcomeIPTrusted); err != nil {
		t.Fatalf("LogIPObservation() error = %v", err)
	}
	if err := hexwallStore.LogIPObservation("203.0.113.20", "wget", OutcomeIPBlocked); err != nil {
		t.Fatalf("LogIPObservation() error = %v", err)
	}

	var count int
	err = hexwallStore.readOnly.QueryRow(`SELECT COUNT(*) FROM ip_observations WHERE ip = ?`, "203.0.113.20").Scan(&count)
	if err != nil {
		t.Fatalf("query ip_observations count error = %v", err)
	}
	if count != 2 {
		t.Fatalf("row count = %d, want 2 for same IP with different programs", count)
	}
}

func TestPruneRemovesStaleIPObservations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexwall.db")

	hexwallStore, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	now := time.Now().Unix()

	// Insert stale ip_observations (older than 7 days).
	staleIP := now - int64(pruneSNIWindow.Seconds()) - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO ip_observations (ip, program, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "203.0.113.50", "curl", "unknown", staleIP, staleIP, 5); err != nil {
		t.Fatalf("insert stale ip_observations error = %v", err)
	}

	// Insert fresh ip_observations.
	freshIP := now - 60
	if _, err := hexwallStore.readWrite.Exec(`
		INSERT INTO ip_observations (ip, program, outcome, first_seen, last_seen, times_seen)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "203.0.113.50", "wget", "unknown", freshIP, freshIP, 1); err != nil {
		t.Fatalf("insert fresh ip_observations error = %v", err)
	}

	// Run prune.
	result, err := hexwallStore.Prune()
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	if result.IPObservations != 1 {
		t.Fatalf("Prune().IPObservations = %d, want 1", result.IPObservations)
	}

	// Verify fresh row remains.
	var count int
	if err := hexwallStore.readOnly.QueryRow(`SELECT COUNT(*) FROM ip_observations`).Scan(&count); err != nil {
		t.Fatalf("query ip_observations count error = %v", err)
	}
	if count != 1 {
		t.Fatalf("ip_observations count = %d, want 1 fresh row remaining", count)
	}
}
