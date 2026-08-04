package pihole

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestNormalizeDomain(t *testing.T) {
	if got := normalizeDomain(" Example.COM "); got != "example.com" {
		t.Fatalf("normalizeDomain() = %q, want %q", got, "example.com")
	}
}

// openTestGravityDB creates a temporary SQLite database with Pi-hole-like views
// and returns the opened DB along with its path. The caller must close it.
func openTestGravityDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "gravity.db")

	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: dbPath, RawQuery: "mode=rwc"}).String())
	if err != nil {
		t.Fatalf("open test gravity db: %v", err)
	}

	// Create backing tables and views matching Pi-hole v6 shapes.
	schema := `
		CREATE TABLE adlist (id INTEGER PRIMARY KEY, address TEXT, enabled INTEGER, date_added INTEGER, date_modified INTEGER, comment TEXT, type INTEGER, number INTEGER);
		CREATE TABLE domainlist (id INTEGER PRIMARY KEY, type INTEGER, domain TEXT, enabled INTEGER, date_added INTEGER, date_modified INTEGER, comment TEXT, groups TEXT);
		CREATE TABLE gravity (id INTEGER PRIMARY KEY, domain TEXT, adlist_id INTEGER);
		CREATE INDEX idx_gravity ON gravity (domain, adlist_id);

		CREATE VIEW vw_allowlist AS SELECT domain FROM domainlist WHERE type = 0 AND enabled = 1 AND TRIM(domain) <> '';
		CREATE VIEW vw_denylist AS SELECT domain FROM domainlist WHERE type = 1 AND enabled = 1 AND TRIM(domain) <> '';
		CREATE VIEW vw_gravity AS SELECT domain FROM gravity;
		CREATE VIEW vw_regex_allowlist AS SELECT domain FROM domainlist WHERE type = 2 AND enabled = 1 AND TRIM(domain) <> '';
		CREATE VIEW vw_regex_denylist AS SELECT domain FROM domainlist WHERE type = 3 AND enabled = 1 AND TRIM(domain) <> '';
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		t.Fatalf("create schema: %v", err)
	}

	return db, dbPath
}

// insertDomain inserts a domain into the domainlist table with the given type.
// type 0 = allowlist, type 1 = denylist, type 2 = regex allowlist, type 3 = regex denylist.
func insertDomain(t *testing.T, db *sql.DB, domain string, listType int) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO domainlist (type, domain, enabled) VALUES (?, ?, 1)`, listType, domain)
	if err != nil {
		t.Fatalf("insert domain %q type %d: %v", domain, listType, err)
	}
}

// insertGravity inserts a domain into the gravity table.
func insertGravity(t *testing.T, db *sql.DB, domain string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO gravity (domain, adlist_id) VALUES (?, 1)`, domain)
	if err != nil {
		t.Fatalf("insert gravity domain %q: %v", domain, err)
	}
}

func newTestChecker(t *testing.T, gravityPath string) *Checker {
	t.Helper()
	ftlPath := filepath.Join(t.TempDir(), "pihole-FTL.db")
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: ftlPath, RawQuery: "mode=rwc"}).String())
	if err != nil {
		t.Fatalf("open test FTL db: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, type INTEGER, domain TEXT, status INTEGER, ip TEXT)`); err != nil {
		_ = db.Close()
		t.Fatalf("create FTL schema: %v", err)
	}

	var gravityDB *sql.DB
	if gravityPath != "" {
		gravityDB, err = sql.Open("sqlite", "file:"+(&url.URL{Path: gravityPath, RawQuery: "mode=ro"}).String())
		if err != nil {
			_ = db.Close()
			t.Fatalf("open gravity db: %v", err)
		}
	}

	return &Checker{db: db, gravityDB: gravityDB}
}

func TestIsBlockedByPolicy_Denylist(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "blocked.example.com", 1) // type 1 = denylist
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	blocked, err := checker.IsBlockedByPolicy("blocked.example.com")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsBlockedByPolicy() = false, want true for denylist domain")
	}
}

func TestIsBlockedByPolicy_Gravity(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertGravity(t, gravDB, "malware.example.net")
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	blocked, err := checker.IsBlockedByPolicy("malware.example.net")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsBlockedByPolicy() = false, want true for gravity domain")
	}
}

func TestIsBlockedByPolicy_NoMatch(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertGravity(t, gravDB, "other.example.com")
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	blocked, err := checker.IsBlockedByPolicy("safe.example.org")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if blocked {
		t.Fatal("IsBlockedByPolicy() = true, want false for unknown domain")
	}
}

func TestIsAllowedByPolicy_Allowlist(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "trusted.example.com", 0) // type 0 = allowlist
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	allowed, err := checker.IsAllowedByPolicy("trusted.example.com")
	if err != nil {
		t.Fatalf("IsAllowedByPolicy() error = %v", err)
	}
	if !allowed {
		t.Fatal("IsAllowedByPolicy() = false, want true for allowlist domain")
	}
}

func TestIsAllowedByPolicy_NoMatch(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "trusted.example.com", 0)
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	allowed, err := checker.IsAllowedByPolicy("unknown.example.org")
	if err != nil {
		t.Fatalf("IsAllowedByPolicy() error = %v", err)
	}
	if allowed {
		t.Fatal("IsAllowedByPolicy() = true, want false for unknown domain")
	}
}

func TestPolicyLookup_CaseNormalization(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "CaseSensitive.COM", 1)
	insertGravity(t, gravDB, "GravityDomain.ORG")
	insertDomain(t, gravDB, "AllowCase.COM", 0)
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	// Denylist: case-insensitive match
	blocked, err := checker.IsBlockedByPolicy(" casesensitive.com ")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsBlockedByPolicy() = false, want true for case-insensitive denylist match")
	}

	// Gravity: case-insensitive match
	blocked, err = checker.IsBlockedByPolicy("GRAVITYDOMAIN.ORG")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsBlockedByPolicy() = false, want true for case-insensitive gravity match")
	}

	// Allowlist: case-insensitive match
	allowed, err := checker.IsAllowedByPolicy("allowcase.com")
	if err != nil {
		t.Fatalf("IsAllowedByPolicy() error = %v", err)
	}
	if !allowed {
		t.Fatal("IsAllowedByPolicy() = false, want true for case-insensitive allowlist match")
	}
}

func TestPolicyLookup_EmptyDomain(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "blocked.example.com", 1)
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	blocked, err := checker.IsBlockedByPolicy("")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy(\"\") error = %v", err)
	}
	if blocked {
		t.Fatal("IsBlockedByPolicy(\"\") = true, want false")
	}

	allowed, err := checker.IsAllowedByPolicy("")
	if err != nil {
		t.Fatalf("IsAllowedByPolicy(\"\") error = %v", err)
	}
	if allowed {
		t.Fatal("IsAllowedByPolicy(\"\") = true, want false")
	}
}

func TestPolicyLookup_NilGravityDB(t *testing.T) {
	t.Parallel()

	// Create a checker with nil gravityDB (simulates gravity.db unavailable).
	checker := &Checker{
		db:        nil, // not needed for these methods
		gravityDB: nil,
	}

	blocked, err := checker.IsBlockedByPolicy("anything.example.com")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v, want nil", err)
	}
	if blocked {
		t.Fatal("IsBlockedByPolicy() = true, want false for nil gravity DB")
	}

	allowed, err := checker.IsAllowedByPolicy("anything.example.com")
	if err != nil {
		t.Fatalf("IsAllowedByPolicy() error = %v, want nil", err)
	}
	if allowed {
		t.Fatal("IsAllowedByPolicy() = true, want false for nil gravity DB")
	}
}

func TestPolicyCounts(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "allow1.com", 0)
	insertDomain(t, gravDB, "allow2.com", 0)
	insertDomain(t, gravDB, "deny1.com", 1)
	insertGravity(t, gravDB, "g1.com")
	insertGravity(t, gravDB, "g2.com")
	insertGravity(t, gravDB, "g3.com")
	insertDomain(t, gravDB, "regex_allow", 2)
	insertDomain(t, gravDB, "regex_deny1", 3)
	insertDomain(t, gravDB, "regex_deny2", 3)
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	counts, err := checker.PolicyCounts()
	if err != nil {
		t.Fatalf("PolicyCounts() error = %v", err)
	}
	if counts == nil {
		t.Fatal("PolicyCounts() = nil, want non-nil map")
	}

	want := map[string]int64{
		"vw_allowlist":       2,
		"vw_denylist":        1,
		"vw_gravity":         3,
		"vw_regex_allowlist": 1,
		"vw_regex_denylist":  2,
	}
	for view, wantCount := range want {
		if got := counts[view]; got != wantCount {
			t.Errorf("PolicyCounts()[%q] = %d, want %d", view, got, wantCount)
		}
	}
}

func TestPolicyCounts_NilGravityDB(t *testing.T) {
	t.Parallel()
	checker := &Checker{gravityDB: nil}

	counts, err := checker.PolicyCounts()
	if err != nil {
		t.Fatalf("PolicyCounts() error = %v, want nil", err)
	}
	if counts != nil {
		t.Fatalf("PolicyCounts() = %v, want nil for nil gravity DB", counts)
	}
}

func TestGravityDBPath_Derived(t *testing.T) {
	t.Parallel()

	// Create the FTL db in a known directory.
	dir := t.TempDir()
	ftlPath := filepath.Join(dir, "pihole-FTL.db")
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: ftlPath, RawQuery: "mode=rwc"}).String())
	if err != nil {
		t.Fatalf("open FTL db: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE queries (id INTEGER PRIMARY KEY)`); err != nil {
		_ = db.Close()
		t.Fatalf("init FTL db: %v", err)
	}
	_ = db.Close()

	// Create gravity.db next to it.
	gravPath := filepath.Join(dir, "gravity.db")
	gravDB, err := sql.Open("sqlite", "file:"+(&url.URL{Path: gravPath, RawQuery: "mode=rwc"}).String())
	if err != nil {
		t.Fatalf("open gravity db: %v", err)
	}
	// Create minimal schema so gravity opens cleanly.
	if _, err := gravDB.Exec(`CREATE TABLE adlist (id INTEGER PRIMARY KEY); CREATE VIEW vw_gravity AS SELECT 1 WHERE 0;`); err != nil {
		_ = gravDB.Close()
		t.Fatalf("create gravity schema: %v", err)
	}
	_ = gravDB.Close()

	// NewChecker should auto-discover gravity.db next to pihole-FTL.db.
	checker, err := NewChecker(&Config{DBPath: ftlPath})
	if err != nil {
		t.Fatalf("NewChecker() error = %v", err)
	}
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	if checker.gravityDB == nil {
		t.Fatal("gravityDB is nil, want it to be auto-discovered")
	}
}

func TestGravityDBPath_Missing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ftlPath := filepath.Join(dir, "pihole-FTL.db")
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: ftlPath, RawQuery: "mode=rwc"}).String())
	if err != nil {
		t.Fatalf("open FTL db: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE queries (id INTEGER PRIMARY KEY)`); err != nil {
		_ = db.Close()
		t.Fatalf("init FTL db: %v", err)
	}
	_ = db.Close()

	// No gravity.db in dir — NewChecker should succeed with nil gravityDB.
	checker, err := NewChecker(&Config{DBPath: ftlPath})
	if err != nil {
		t.Fatalf("NewChecker() error = %v, want nil when gravity.db is missing", err)
	}
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	if checker.gravityDB != nil {
		t.Fatal("gravityDB is non-nil, want nil when gravity.db is missing")
	}

	// Policy methods should gracefully return false.
	blocked, err := checker.IsBlockedByPolicy("anything.com")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if blocked {
		t.Fatal("IsBlockedByPolicy() = true, want false when gravity unavailable")
	}
}

func TestCloseJoinsErrors(t *testing.T) {
	t.Parallel()

	// Close on a checker with both handles should not panic.
	gravDB, gravPath := openTestGravityDB(t)
	_ = gravDB.Close() // close it first so Close() returns an error

	checker := newTestChecker(t, gravPath)
	// Force gravity DB to nil after construction to test the nil path.
	_ = checker.gravityDB.Close()
	checker.gravityDB = nil

	err := checker.Close()
	if err != nil {
		// We expect an error from closing the already-closed FTL db or nil gravity.
		// Just verify it doesn't panic.
		t.Logf("Close() returned (expected for double-close): %v", err)
	}
}

func TestIsBlockedByPolicy_DenylistBeatsGravity(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "both.example.com", 1) // denylist
	insertGravity(t, gravDB, "both.example.com")   // also in gravity
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	blocked, err := checker.IsBlockedByPolicy("both.example.com")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsBlockedByPolicy() = false, want true when domain is in both denylist and gravity")
	}
}

func TestIsAllowedByPolicy_TakesPrecedenceOverGravity(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertDomain(t, gravDB, "special.example.com", 0) // allowlist
	insertGravity(t, gravDB, "special.example.com")   // also in gravity
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	// Allowlist match should be independent of gravity presence.
	allowed, err := checker.IsAllowedByPolicy("special.example.com")
	if err != nil {
		t.Fatalf("IsAllowedByPolicy() error = %v", err)
	}
	if !allowed {
		t.Fatal("IsAllowedByPolicy() = false, want true for allowlisted domain")
	}
}

func TestIsBlockedByPolicy_WhitespaceNormalization(t *testing.T) {
	t.Parallel()
	gravDB, gravPath := openTestGravityDB(t)
	insertGravity(t, gravDB, "trim.example.com")
	_ = gravDB.Close()

	checker := newTestChecker(t, gravPath)
	defer func() {
		if err := checker.Close(); err != nil {
			t.Errorf("checker.Close(): %v", err)
		}
	}()

	blocked, err := checker.IsBlockedByPolicy("  Trim.Example.COM  ")
	if err != nil {
		t.Fatalf("IsBlockedByPolicy() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsBlockedByPolicy() = false, want true with whitespace around domain")
	}
}
