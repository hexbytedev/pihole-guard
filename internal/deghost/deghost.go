// Package deghost wraps the external fraud API used for IP reputation checks.
// It converts remote responses into local kill-policy decisions.
package deghost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Client calls the external fraud API used for IP reputation checks.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// IPReport matches the API payload for IP fraud checks.
type IPReport struct {
	IP       string         `json:"ip"`
	Security SecurityReport `json:"security"`
}

// SecurityReport describes fraud and anonymity signals for an IP.
type SecurityReport struct {
	IsAbuser        bool `json:"is_abuser"`
	IsAttacker      bool `json:"is_attacker"`
	IsBogon         bool `json:"is_bogon"`
	IsCloudProvider bool `json:"is_cloud_provider"`
	IsProxy         bool `json:"is_proxy"`
	IsRelay         bool `json:"is_relay"`
	IsTor           bool `json:"is_tor"`
	IsTorExit       bool `json:"is_tor_exit"`
	IsVPN           bool `json:"is_vpn"`
	IsAnonymous     bool `json:"is_anonymous"`
	IsThreat        bool `json:"is_threat"`
}

// NewClient creates a Client for the given API base URL.
func NewClient(baseURL string, timeout time.Duration) *Client {
	trimmed := strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL: trimmed,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// CheckIP fetches a fraud report for a single IP.
// It returns a nil report and nil error for HTTP 403 responses, which the API uses for private or reserved IPs.
func (c *Client) CheckIP(ctx context.Context, ip string) (*IPReport, error) {
	if c == nil {
		return nil, errors.New("nil deghost client")
	}
	if c.httpClient == nil {
		return nil, errors.New("nil deghost http client")
	}

	baseURL := strings.TrimSpace(c.baseURL)
	if baseURL == "" {
		return nil, errors.New("deghost base URL is required")
	}

	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, errors.New("ip is required")
	}

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid ip %q: %w", ip, err)
	}

	endpoint, err := url.JoinPath(baseURL, "ip", parsedIP.String())
	if err != nil {
		return nil, fmt.Errorf("build endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusForbidden {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deghost returned status %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var report IPReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &report, nil
}

// ShouldKill reports whether the report matches the current kill policy.
func ShouldKill(report *IPReport) bool {
	if report == nil {
		return false
	}

	return report.Security.IsAbuser || report.Security.IsAttacker || report.Security.IsThreat
}

// DomainReport matches the API payload for domain reputation checks.
type DomainReport struct {
	Status          string `json:"status"`
	HasMX           bool   `json:"has_mx"`
	Disposable      bool   `json:"disposable"`
	Spam            bool   `json:"spam"`
	PublicDomain    bool   `json:"public_domain"`
	RelayDomain     bool   `json:"relay_domain"`
	Blacklisted     bool   `json:"blacklisted"`
	DomainAgeInDays int    `json:"domain_age_in_days"`
}

// CheckDomain fetches a reputation report for a single domain.
// Unlike CheckIP's 403 handling (nil report for private/reserved IPs), this endpoint
// returns a real JSON body on HTTP 200, 400, and 403 — all are decoded into a DomainReport.
// Only 499/504/500/other status codes are treated as hard errors.
func (c *Client) CheckDomain(ctx context.Context, domain string) (*DomainReport, error) {
	if c == nil {
		return nil, errors.New("nil deghost client")
	}
	if c.httpClient == nil {
		return nil, errors.New("nil deghost http client")
	}

	baseURL := strings.TrimSpace(c.baseURL)
	if baseURL == "" {
		return nil, errors.New("deghost base URL is required")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, errors.New("domain is required")
	}

	endpoint, err := url.JoinPath(baseURL, "domain", domain)
	if err != nil {
		return nil, fmt.Errorf("build endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
		return nil, fmt.Errorf("deghost returned status %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var report DomainReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &report, nil
}

// ShouldBlockDomain reports whether the domain report matches the current block policy.
// It triggers only on explicit negative signals (status "not_allowed" or blacklisted),
// ignoring softer signals like disposable, spam, or domain age which are too noisy
// to act on alone — consistent with how ShouldKill only fires on explicit threat fields.
func ShouldBlockDomain(report *DomainReport) bool {
	if report == nil {
		return false
	}

	return report.Status == "not_allowed" || report.Blacklisted
}
