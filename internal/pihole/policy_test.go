package pihole

import (
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	if got := normalizeDomain(" Example.COM "); got != "example.com" {
		t.Fatalf("normalizeDomain() = %q, want %q", got, "example.com")
	}
}
