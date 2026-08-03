package pihole

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hexbytedev/hexwall/internal/store"
)

const (
	refreshLookback      = time.Hour
	lookupTimeout        = time.Second
	maxConcurrentLookups = 32
)

// IPCache resolves Pi-hole domains to IPs and writes them to the store.
// The store owns the trusted-IP set, and this type only drives the refresh cycle.
type IPCache struct {
	checker *Checker
	store   *store.Store
}

// NewIPCache creates an IPCache backed by the given Checker and Store.
func NewIPCache(checker *Checker, store *store.Store) *IPCache {
	return &IPCache{
		checker: checker,
		store:   store,
	}
}

// Refresh queries Pi-hole for recent domains, resolves them with bounded concurrency,
// and upserts the resulting unique IPs into the store.
func (c *IPCache) Refresh(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	since := time.Now().Add(-refreshLookback).Unix()

	domains, err := c.checker.DomainsSeenSince(since)
	if err != nil {
		slog.Error("cache refresh: failed to query pi-hole domains", "err", err)
		return
	}
	if len(domains) == 0 {
		slog.Info("cache refreshed", "domains", 0, "ips", 0)
		return
	}

	sort.Strings(domains)

	sem := make(chan struct{}, maxConcurrentLookups)

	// Workers write straight into resolved under mu. Using a shared map instead of a
	// results channel keeps a worker from ever blocking on a consumer that has not
	// started yet, which would otherwise pin its slot in sem and stall the spawn loop.
	var mu sync.Mutex
	resolved := make(map[string][]string, len(domains))

	var wg sync.WaitGroup
spawnLoop:
	for _, domain := range domains {
		select {
		case <-ctx.Done():
			break spawnLoop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()

			rctx, cancel := context.WithTimeout(ctx, lookupTimeout)
			defer cancel()

			ips, err := net.DefaultResolver.LookupHost(rctx, d)
			if err != nil {
				// DNS failure is normal for blocked domains, expired records, and similar cases.
				return
			}

			mu.Lock()
			resolved[d] = ips
			mu.Unlock()
		}(domain)
	}

	wg.Wait()

	if ctx.Err() != nil {
		return
	}

	// A shared CDN edge IP serves many unrelated domains, so keep the full set per IP.
	// domains is sorted, so each IP's slice stays in a stable order and its first entry
	// is the one recorded as the representative domain in allowed_ips.
	ipDomains := make(map[string][]string, len(resolved))
	seen := make(map[string]struct{}, len(resolved))
	for _, domain := range domains {
		ips, ok := resolved[domain]
		if !ok {
			continue
		}

		for _, ip := range ips {
			key := ip + "\x00" + domain
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			ipDomains[ip] = append(ipDomains[ip], domain)
		}
	}

	var totalIPs int
	var totalPairs int
	for ip, ipDomainSet := range ipDomains {
		if err := c.store.UpsertAllowedIP(ip, ipDomainSet[0]); err != nil {
			slog.Error("cache refresh: failed to upsert IP", "ip", ip, "domain", ipDomainSet[0], "err", err)
		} else {
			totalIPs++
		}

		for _, domain := range ipDomainSet {
			if err := c.store.UpsertAllowedIPDomain(ip, domain); err != nil {
				slog.Error("cache refresh: failed to upsert IP domain", "ip", ip, "domain", domain, "err", err)
			} else {
				totalPairs++
			}
		}
	}

	slog.Info("cache refreshed", "domains", len(domains), "ips", totalIPs, "pairs", totalPairs)
}

// RunRefresh calls Refresh on the given interval until ctx is cancelled.
func (c *IPCache) RunRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		slog.Error("cache refresh: invalid interval", "interval", interval)
		return
	}

	c.Refresh(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Refresh(ctx)
		}
	}
}
