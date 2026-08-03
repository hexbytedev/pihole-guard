// Package monitor scans active network connections against the hexwall store.
// It logs or kills untrusted connections based on the selected mode.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hexbytedev/hexwall/internal/allowlist"
	"github.com/hexbytedev/hexwall/internal/deghost"
	"github.com/hexbytedev/hexwall/internal/enforcer"
	"github.com/hexbytedev/hexwall/internal/pihole"
	"github.com/hexbytedev/hexwall/internal/somo"
	"github.com/hexbytedev/hexwall/internal/store"
	"github.com/hexbytedev/hexwall/internal/zeek"
)

const (
	// ModeWatch logs suspicious connections without killing them.
	ModeWatch = "watch"
	// ModeEnforce kills suspicious connections and records the action.
	ModeEnforce = "enforce"
)

// scanSummary tracks per-scan outcome counts for the summary line.
type scanSummary struct {
	connections int
	allowlisted int
	withSNI     int
	withoutSNI  int
	trusted     int
	blocked     int
	unknown     int
	errored     int
}

func normalizeMode(mode string) string {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case ModeEnforce:
		return ModeEnforce
	default:
		return ModeWatch
	}
}

func remoteIP(address string) (net.IP, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, fmt.Errorf("empty remote address")
	}

	if host, _, err := net.SplitHostPort(address); err == nil {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("invalid host %q", host)
		}

		return ip, nil
	}

	address = strings.TrimPrefix(address, "[")
	address = strings.TrimSuffix(address, "]")

	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid address %q", address)
	}

	return ip, nil
}

// HandleZeekEvent evaluates a Zeek notice event against the current policy and persists it.
func HandleZeekEvent(checker *pihole.Checker, hexwallStore *store.Store, mode string, event zeek.Event) {
	if checker == nil || hexwallStore == nil {
		return
	}
	if event.SNI == "" {
		return
	}

	selectedMode := normalizeMode(mode)
	blocked, err := checker.IsBlockedByPolicy(event.SNI)
	if err != nil {
		slog.Warn("zeek policy lookup failed", "sni", event.SNI, "err", err)
		return
	}

	confidence := "medium"
	actionTaken := "logged"
	if blocked {
		confidence = "high"
		slog.Warn("zeek bypass alert", "src_ip", event.SrcIP, "dst_ip", event.DstIP, "dst_port", event.DstPort, "sni", event.SNI, "mode", selectedMode)
	} else {
		slog.Info("zeek notice was not policy-blocked", "src_ip", event.SrcIP, "dst_ip", event.DstIP, "dst_port", event.DstPort, "sni", event.SNI)
	}

	if err := hexwallStore.LogZeekAlert(event.SrcIP, event.DstIP, event.DstPort, event.SNI, blocked, confidence, actionTaken); err != nil {
		slog.Error("failed to persist zeek alert", "src_ip", event.SrcIP, "sni", event.SNI, "err", err)
	}

	if selectedMode == ModeEnforce && blocked {
		slog.Info("enforce mode: zeek alert recorded without direct connection kill", "src_ip", event.SrcIP, "sni", event.SNI)
	}
}

// RunScan inspects established connections and applies the decision ladder.
//
// The ladder is ordered from cheapest/most-authoritative to most-expensive/least-authoritative:
//  1. Static CIDR allowlist (loopback, RFC1918, cloud metadata)
//  2. Zeek SNI presence — if no SNI, fall back to IP-only evaluation (step 7)
//  3. Pi-hole explicit allowlist (user intent, highest authority)
//  4. Pi-hole explicit denylist / gravity (user intent)
//  5. Inferred trust from DNS history (hexwall's own cache)
//  6. Unknown domain → deghost escalation if enabled; no action if disabled
//  7. IP-only fallback → deghost escalation if enabled; no action if disabled
//
// Safety property: with deghost disabled, only rung 4 (Pi-hole blocklist match) can kill.
func RunScan(ctx context.Context, checker *pihole.Checker, hexwallStore *store.Store, deghostClient *deghost.Client, deghostIP bool, deghostDomain bool, zeekClient *zeek.Client, mode string, debug bool) {
	if hexwallStore == nil {
		slog.Error("scan aborted: nil hexwall store")
		return
	}

	selectedMode := normalizeMode(mode)
	if selectedMode != mode {
		slog.Warn("invalid scan mode; defaulting to watch", "mode", mode, "fallback", selectedMode)
	}

	connections, err := somo.GetEstablishedConnections()
	if err != nil {
		slog.Error("error fetching connections", "err", err)
		return
	}

	if len(connections) == 0 {
		slog.Info("scan returned zero connections")
		return
	}

	var summary scanSummary
	summary.connections = len(connections)

	for _, conn := range connections {
		ip, err := remoteIP(conn.RAddress)
		if err != nil {
			slog.Warn("invalid IP address", "address", conn.RAddress, "err", err)
			summary.errored++
			continue
		}

		ipStr := ip.String()

		// Rung 1: static CIDR allowlist.
		if allowlist.Contains(ip) {
			summary.allowlisted++
			summary.trusted++
			continue
		}

		// Rung 2: did Zeek see an SNI for this connection?
		var sniDomain string
		sniFound := false
		if zeekClient != nil {
			if domain, ok := zeekClient.Lookup(conn.LPort, ipStr, conn.RPort); ok {
				sniDomain = domain
				sniFound = true
				summary.withSNI++
			} else {
				summary.withoutSNI++
			}
		} else {
			summary.withoutSNI++
		}

		if !sniFound {
			// Rung 7: IP-only fallback — no SNI means non-TLS, pre-existing connection, or ECH.
			action := evaluateIPOnly(ctx, hexwallStore, deghostClient, deghostIP, checker, ipStr, conn, selectedMode, debug)
			applyOutcome(&summary, action)
			continue
		}

		domain := strings.ToLower(strings.TrimSpace(sniDomain))

		// Rung 3: Pi-hole explicit allowlist — user intent outranks everything inferred.
		allowed, err := checker.IsAllowedByPolicy(domain)
		if err != nil {
			// Fail-open: if we cannot determine whether a domain is explicitly allowed,
			// we must not act on a block from rung 4.  Rung 4 is the only rung that can
			// kill a connection, and killing a legitimate connection on the basis of
			// incomplete policy data is worse than missing one block.
			slog.Warn("domain allowlist lookup failed, skipping blocklist check", "domain", domain, "err", err)
		} else if allowed {
			if logErr := hexwallStore.LogSNIObservation(ipStr, domain, conn.LPort, store.OutcomePolicyAllowed); logErr != nil {
				slog.Debug("failed to log sni observation", "ip", ipStr, "err", logErr)
			}
			summary.trusted++
			continue
		}

		// Rung 4: Pi-hole explicit denylist / gravity — only rung that can kill.
		if err == nil {
			if blocked, err := checker.IsBlockedByPolicy(domain); err != nil {
				slog.Warn("domain denylist lookup failed", "domain", domain, "err", err)
			} else if blocked {
				if logErr := hexwallStore.LogSNIObservation(ipStr, domain, conn.LPort, store.OutcomePolicyBlocked); logErr != nil {
					slog.Debug("failed to log sni observation", "ip", ipStr, "err", logErr)
				}
				slog.Warn("policy-blocked domain", "domain", domain, "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
				applyBlockedOutcome(hexwallStore, selectedMode, ipStr, conn)
				summary.blocked++
				continue
			}
		}

		// Rung 5: inferred trust from DNS history — scoped to this IP.
		known := false
		knownDomains, err := hexwallStore.DomainsForIP(ipStr)
		if err != nil {
			slog.Debug("sni domain check failed", "domain", domain, "ip", ipStr, "err", err)
		} else {
			for _, knownDomain := range knownDomains {
				if pihole.DomainMatches(domain, knownDomain) {
					known = true
					break
				}
			}
		}
		outcome := store.OutcomeUnknown
		if known {
			outcome = store.OutcomeIPDomainMatch
		}
		if logErr := hexwallStore.LogSNIObservation(ipStr, domain, conn.LPort, outcome); logErr != nil {
			slog.Debug("failed to log sni observation", "ip", ipStr, "err", logErr)
		}

		if known {
			summary.trusted++
			continue
		}

		// Rung 6: unknown domain — deghost escalation if enabled.
		if !deghostDomain {
			if debug {
				slog.Info("unknown domain, deghost disabled; no action", "domain", domain, "ip", ipStr, "program", conn.Program)
			}
			summary.unknown++
			continue
		}

		shouldBlock, reason := false, ""

		if cached, err := hexwallStore.GetRecentDomainCheck(domain); err != nil {
			slog.Error("domain cache lookup failed", "domain", domain, "err", err)
			summary.errored++
			continue
		} else if cached != nil {
			shouldBlock = cached.ShouldBlock
			reason = "cached-domain-check"
		}

		if !shouldBlock && reason == "" {
			report, err := deghostClient.CheckDomain(ctx, domain)
			if err != nil {
				slog.Error("deghost domain check failed", "domain", domain, "program", conn.Program, "err", err)
				summary.errored++
				continue
			}

			shouldBlock = deghost.ShouldBlockDomain(report)
			reason = "live-domain-check"
			if err := hexwallStore.UpsertDomainCheck(domain, shouldBlock); err != nil {
				slog.Error("failed to cache domain check", "domain", domain, "program", conn.Program, "err", err)
			}
		}

		if !shouldBlock {
			if debug {
				slog.Info("unknown but clean domain", "domain", domain, "ip", ipStr, "program", conn.Program, "reason", reason)
			}
			summary.unknown++
			continue
		}

		slog.Warn("deghost-blocked domain", "domain", domain, "address", conn.RAddress, "pid", conn.PID, "program", conn.Program, "reason", reason)
		applyBlockedOutcome(hexwallStore, selectedMode, ipStr, conn)
		summary.blocked++
	}

	fmt.Printf("[%s] Scan complete: %d connections, %d trusted, %d blocked, %d unknown (allowlisted=%d sni=%d no-sni=%d errored=%d)\n",
		time.Now().Format("15:04:05"), summary.connections, summary.trusted, summary.blocked, summary.unknown, summary.allowlisted, summary.withSNI, summary.withoutSNI, summary.errored)
}

// evaluateIPOnly handles the IP-only fallback path (rung 7) when no SNI is available.
// It returns "trusted", "blocked", "unknown", or "error".
// Every exit path records an IP observation before returning.
func evaluateIPOnly(ctx context.Context, hexwallStore *store.Store, deghostClient *deghost.Client, deghostIP bool, checker *pihole.Checker, ipStr string, conn somo.Connection, mode string, debug bool) string {
	allowed, err := hexwallStore.IsAllowed(ipStr)
	if err != nil {
		slog.Error("store lookup failed", "address", conn.RAddress, "err", err)
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "error"
	}

	if allowed {
		if err := hexwallStore.UpdateEstablished(ipStr); err != nil {
			slog.Error("failed to update established", "address", conn.RAddress, "err", err)
		}
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPTrusted); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "trusted"
	}

	if !deghostIP {
		if debug {
			slog.Info("unknown IP, deghost disabled; no action", "ip", ipStr, "program", conn.Program)
		}
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "unknown"
	}

	cachedFraudCheck, err := hexwallStore.GetRecentFraudCheck(ipStr)
	if err != nil {
		slog.Error("fraud cache lookup failed", "ip", ipStr, "program", conn.Program, "err", err)
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "error"
	}

	if cachedFraudCheck != nil {
		if !cachedFraudCheck.ShouldKill {
			if debug {
				slog.Info("unknown but clean IP (cached)", "ip", ipStr, "program", conn.Program)
			}
			if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
				slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
			}
			return "unknown"
		}

		slog.Warn("deghost-blocked IP (cached)", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPBlocked); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		applyBlockedOutcome(hexwallStore, mode, ipStr, conn)
		return "blocked"
	}

	report, err := deghostClient.CheckIP(ctx, ipStr)
	if err != nil {
		slog.Error("deghost check failed", "ip", ipStr, "program", conn.Program, "err", err)
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "error"
	}

	if report == nil {
		if err := hexwallStore.UpsertFraudCheck(ipStr, false); err != nil {
			slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
		}
		if debug {
			slog.Info("unknown but clean IP (private/reserved)", "ip", ipStr, "program", conn.Program)
		}
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPReserved); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "unknown"
	}

	shouldKill := deghost.ShouldKill(report)
	if err := hexwallStore.UpsertFraudCheck(ipStr, shouldKill); err != nil {
		slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
	}

	if !shouldKill {
		if debug {
			slog.Info("unknown but clean IP", "ip", ipStr, "program", conn.Program)
		}
		if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPUnknown); logErr != nil {
			slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
		}
		return "unknown"
	}

	slog.Warn("deghost-blocked IP", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
	if logErr := hexwallStore.LogIPObservation(ipStr, conn.Program, store.OutcomeIPBlocked); logErr != nil {
		slog.Debug("failed to log ip observation", "ip", ipStr, "err", logErr)
	}
	applyBlockedOutcome(hexwallStore, mode, ipStr, conn)
	return "blocked"
}

// applyBlockedOutcome enforces the kill/watch policy for a blocked connection.
func applyBlockedOutcome(hexwallStore *store.Store, mode, ipStr string, conn somo.Connection) {
	selectedMode := normalizeMode(mode)
	if selectedMode == ModeWatch {
		slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
		return
	}

	if err := hexwallStore.LogKill(ipStr, conn.PID, conn.Program); err != nil {
		slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
	}

	// Connection-level termination via `ss -K` (requires CONFIG_INET_DIAG_DESTROY)
	// is deferred work.  KillProcess terminates the owning process, which is coarser.
	pidInt, err := enforcer.ParsePID(conn.PID)
	if err != nil {
		slog.Warn("invalid PID, skipping kill", "pid", conn.PID, "address", conn.RAddress, "err", err)
		return
	}
	if err := enforcer.KillProcess(pidInt, conn.Program, conn.RAddress); err != nil {
		slog.Warn("failed to kill process", "address", conn.RAddress, "pid", conn.PID, "err", err)
	} else {
		slog.Info("killed connection", "address", conn.RAddress)
	}
}

// applyOutcome increments the appropriate summary counter for a given outcome string.
func applyOutcome(summary *scanSummary, outcome string) {
	switch outcome {
	case "trusted":
		summary.trusted++
	case "blocked":
		summary.blocked++
	case "unknown":
		summary.unknown++
	case "error":
		summary.errored++
	}
}
