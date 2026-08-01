package zeek

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestClient builds a Client pointed at path without starting the
// background tailLoop goroutine, so tests can call processNewLines directly
// at controlled points instead of racing a real ticker.
func newTestClient(t *testing.T, path string) *Client {
	t.Helper()
	return &Client{
		logPath: path,
		cache:   make(map[string]sniEntry),
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func TestParseNoticeLine(t *testing.T) {
	line := `{"note":"DNSBypass::PossibleBypass","src_ip":"192.0.2.10","dst_ip":"203.0.113.20","dst_port":"443","sni":"evil.example","msg":"SNI evil.example from 192.0.2.10"}`

	event, err := ParseNoticeLine(line)
	if err != nil {
		t.Fatalf("ParseNoticeLine() error = %v", err)
	}

	if event.SrcIP != "192.0.2.10" {
		t.Fatalf("ParseNoticeLine().SrcIP = %q, want %q", event.SrcIP, "192.0.2.10")
	}
	if event.DstIP != "203.0.113.20" {
		t.Fatalf("ParseNoticeLine().DstIP = %q, want %q", event.DstIP, "203.0.113.20")
	}
	if event.DstPort != "443" {
		t.Fatalf("ParseNoticeLine().DstPort = %q, want %q", event.DstPort, "443")
	}
	if event.SNI != "evil.example" {
		t.Fatalf("ParseNoticeLine().SNI = %q, want %q", event.SNI, "evil.example")
	}
	if event.Timestamp.IsZero() {
		t.Fatal("ParseNoticeLine().Timestamp = zero time, want non-zero")
	}
	if event.Timestamp.After(time.Now().Add(time.Second)) {
		t.Fatalf("ParseNoticeLine().Timestamp too far in the future: %v", event.Timestamp)
	}
}

func TestParseNoticeLineRejectsInvalidJSON(t *testing.T) {
	_, err := ParseNoticeLine(`{"note":`)
	if err == nil {
		t.Fatal("ParseNoticeLine() error = nil, want error")
	}
}

func TestClientProcessNewLines_BasicParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443,"server_name":"example.com"}`+"\n")

	c := newTestClient(t, path)
	c.processNewLines()

	domain, ok := c.Lookup("51820", "203.0.113.20", "443")
	if !ok {
		t.Fatal("Lookup() ok = false, want true")
	}
	if domain != "example.com" {
		t.Fatalf("Lookup() domain = %q, want %q", domain, "example.com")
	}

	// The reverse orientation must also resolve, since Lookup doesn't know
	// in advance which side of the connection is the local endpoint.
	domain, ok = c.Lookup("443", "10.0.0.5", "51820")
	if !ok {
		t.Fatal("Lookup() reverse orientation ok = false, want true")
	}
	if domain != "example.com" {
		t.Fatalf("Lookup() reverse orientation domain = %q, want %q", domain, "example.com")
	}
}

func TestClientProcessNewLines_SkipsIncompleteRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443}`+"\n"+
		`not json at all`+"\n"+
		`{"id.orig_h":"","id.orig_p":1,"id.resp_h":"203.0.113.21","id.resp_p":443,"server_name":"missing-orig-host.example"}`+"\n")

	c := newTestClient(t, path)
	c.processNewLines()

	if len(c.cache) != 0 {
		t.Fatalf("cache = %v, want empty (no valid records in input)", c.cache)
	}
}

func TestClientProcessNewLines_PartialLineHeldAcrossTicks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	full := `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443,"server_name":"example.com"}` + "\n"

	// Simulate Zeek flushing mid-record: only the first half of the line
	// lands before the poll fires.
	split := len(full) / 2
	writeFile(t, path, full[:split])

	c := newTestClient(t, path)
	c.processNewLines()

	if _, ok := c.Lookup("51820", "203.0.113.20", "443"); ok {
		t.Fatal("Lookup() found a record from a partial line, want none yet")
	}
	if len(c.pending) == 0 {
		t.Fatal("pending is empty, want the partial line to be held over")
	}

	// The rest of the line arrives on the next tick.
	writeFile(t, path, full)
	c.processNewLines()

	domain, ok := c.Lookup("51820", "203.0.113.20", "443")
	if !ok {
		t.Fatal("Lookup() ok = false after completing the line, want true")
	}
	if domain != "example.com" {
		t.Fatalf("Lookup() domain = %q, want %q", domain, "example.com")
	}
}

func TestClientProcessNewLines_Rotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	writeFile(t, path, `{"id.orig_h":"10.0.0.5","id.orig_p":51820,"id.resp_h":"203.0.113.20","id.resp_p":443,"server_name":"example.com"}`+"\n")

	c := newTestClient(t, path)
	c.processNewLines()

	if _, ok := c.Lookup("51820", "203.0.113.20", "443"); !ok {
		t.Fatal("Lookup() ok = false before rotation, want true")
	}

	// Rotation: zeekctl closes the current log and starts a fresh, empty
	// file at the same path — simulate the two ticks that straddle that.
	writeFile(t, path, "")
	c.processNewLines()
	writeFile(t, path, `{"id.orig_h":"10.0.0.9","id.orig_p":9000,"id.resp_h":"203.0.113.30","id.resp_p":443,"server_name":"post-rotation.example"}`+"\n")
	c.processNewLines()

	if domain, ok := c.Lookup("9000", "203.0.113.30", "443"); !ok || domain != "post-rotation.example" {
		t.Fatalf("Lookup() after rotation = (%q, %v), want (%q, true)", domain, ok, "post-rotation.example")
	}
}

func TestClientLookup_Expiry(t *testing.T) {
	c := newTestClient(t, "")
	c.cache["51820|203.0.113.20|443"] = sniEntry{
		domain:     "example.com",
		observedAt: time.Now().Add(-entryExpiry - time.Second),
	}

	if _, ok := c.Lookup("51820", "203.0.113.20", "443"); ok {
		t.Fatal("Lookup() ok = true for an expired entry, want false")
	}
}
