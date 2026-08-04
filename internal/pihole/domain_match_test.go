package pihole

import (
	"testing"
)

func TestDomainMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		observed string
		known    string
		want     bool
	}{
		{name: "exact match", observed: "github.com", known: "github.com", want: true},
		{name: "subdomain observed", observed: "www.github.com", known: "github.com", want: true},
		{name: "subdomain known", observed: "github.com", known: "www.github.com", want: true},
		{name: "deeper subdomain", observed: "a.b.github.com", known: "github.com", want: true},
		{name: "deeper subdomain reversed", observed: "github.com", known: "a.b.github.com", want: true},
		{name: "lookalike suffix is not a match", observed: "github.com.evil.com", known: "github.com", want: false},
		{name: "lookalike suffix reversed is not a match", observed: "github.com", known: "github.com.evil.com", want: false},
		{name: "partial label is not a match", observed: "notgithub.com", known: "github.com", want: false},
		{name: "unrelated domains", observed: "example.org", known: "github.com", want: false},
		{name: "empty observed", observed: "", known: "github.com", want: false},
		{name: "empty known", observed: "github.com", known: "", want: false},
		{name: "both empty", observed: "", known: "", want: false},
		{name: "whitespace only", observed: "   ", known: "github.com", want: false},
		{name: "case and whitespace normalized", observed: " GitHub.COM ", known: "github.com", want: true},
		{name: "case and whitespace normalized subdomain", observed: " WWW.GitHub.com ", known: " GITHUB.com ", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := DomainMatches(tt.observed, tt.known); got != tt.want {
				t.Fatalf("DomainMatches(%q, %q) = %v, want %v", tt.observed, tt.known, got, tt.want)
			}
		})
	}
}
