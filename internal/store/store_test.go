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
