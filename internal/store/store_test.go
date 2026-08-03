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
