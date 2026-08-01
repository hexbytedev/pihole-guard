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

func logScanConnection(debug bool, ip, program, status string) {
	if !debug {
		return
	}

	slog.Info("scan connection", "ip", ip, "program", program, "status", status)
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

// RunScan inspects established connections and applies the selected trust and kill policy.
func RunScan(ctx context.Context, checker *pihole.Checker, hexwallStore *store.Store, deghostClient *deghost.Client, zeekClient *zeek.Client, mode string, debug bool) {
	if hexwallStore == nil {
		slog.Error("scan aborted: nil hexwall store")
		return
	}
	if deghostClient == nil {
		slog.Error("scan aborted: nil deghost client")
		return
	}

	selectedMode := normalizeMode(mode)
	if selectedMode != mode {
		slog.Warn("invalid scan mode; defaulting to watch", "mode", mode, "fallback", selectedMode)
	}

	fmt.Printf("[%s] Scanning connections (%s mode)...\n", time.Now().Format("15:04:05"), selectedMode)

	connections, err := somo.GetEstablishedConnections()
	if err != nil {
		slog.Error("error fetching connections", "err", err)
		return
	}

	if len(connections) == 0 {
		slog.Info("scan returned zero connections")
		return
	}

	for _, conn := range connections {
		ip, err := remoteIP(conn.RAddress)
		if err != nil {
			slog.Warn("invalid IP address", "address", conn.RAddress, "err", err)
			continue
		}

		ipStr := ip.String()

		// Trust allowlisted IPs immediately.
		if allowlist.Contains(ip) {
			logScanConnection(debug, ipStr, conn.Program, "allowed")
			continue
		}

		sniBypass := false
		var zeekDomain string
		if zeekClient != nil {
			if domain, ok := zeekClient.Lookup(conn.LPort, ipStr, conn.RPort); ok {
				zeekDomain = domain
				known, err := checker.IsDomainKnown(domain)
				if err != nil {
					slog.Debug("sni domain check failed", "domain", domain, "ip", ipStr, "err", err)
				} else if !known {
					sniBypass = true
					slog.Debug("sni domain not in pihole history, bypassing IP trust", "domain", domain, "ip", ipStr)
				}
				if logErr := hexwallStore.LogSNIObservation(ipStr, domain, conn.LPort, known); logErr != nil {
					slog.Debug("failed to log sni observation", "ip", ipStr, "err", logErr)
				}
			} else {
				slog.Debug("zeek: no SNI seen for connection", "local_port", conn.LPort, "remote_ip", ipStr, "remote_port", conn.RPort)
			}
		}

		if sniBypass {
			shouldBlock, reason := false, ""
			domain := strings.ToLower(strings.TrimSpace(zeekDomain))

			if blocked, err := checker.IsBlockedByPolicy(domain); err != nil {
				slog.Debug("domain policy check failed", "domain", domain, "err", err)
			} else if blocked {
				shouldBlock, reason = true, "policy-blocked"
			}

			if !shouldBlock {
				if cached, err := hexwallStore.GetRecentDomainCheck(domain); err != nil {
					slog.Error("domain cache lookup failed", "domain", domain, "err", err)
					continue
				} else if cached != nil {
					shouldBlock = cached.ShouldBlock
					reason = "cached-domain-check"
				}
			}

			if !shouldBlock && reason == "" {
				report, err := deghostClient.CheckDomain(ctx, domain)
				if err != nil {
					slog.Error("deghost domain check failed", "domain", domain, "program", conn.Program, "err", err)
					continue
				}

				shouldBlock = deghost.ShouldBlockDomain(report)
				reason = "live-domain-check"
				if err := hexwallStore.UpsertDomainCheck(domain, shouldBlock); err != nil {
					slog.Error("failed to cache domain check", "domain", domain, "program", conn.Program, "err", err)
				}
			}

			if !shouldBlock {
				slog.Info("unrecognized but clean domain", "domain", domain, "ip", ipStr, "program", conn.Program, "reason", reason)
				logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
				continue
			}

			logScanConnection(debug, ipStr, conn.Program, "vulnerable")
			slog.Warn("vulnerable connection detected", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program, "reason", reason)
			if selectedMode == ModeWatch {
				slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
				continue
			}

			if err := hexwallStore.LogKill(ipStr, conn.PID, conn.Program); err != nil {
				slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
			}
			if err := somo.KillConnection(conn.PID); err != nil {
				slog.Error("failed to kill connection", "address", conn.RAddress, "pid", conn.PID, "err", err)
			} else {
				slog.Info("killed connection", "address", conn.RAddress)
			}
			continue
		}

		allowed, err := hexwallStore.IsAllowed(ipStr)
		if err != nil {
			slog.Error("store lookup failed", "address", conn.RAddress, "err", err)
			continue
		}

		if allowed {
			logScanConnection(debug, ipStr, conn.Program, "allowed")
			// Keep long-running connections trusted after their Pi-hole refresh window expires.
			if err := hexwallStore.UpdateEstablished(ipStr); err != nil {
				slog.Error("failed to update established", "address", conn.RAddress, "err", err)
			}
			continue
		}

		cachedFraudCheck, err := hexwallStore.GetRecentFraudCheck(ipStr)
		if err != nil {
			slog.Error("fraud cache lookup failed", "ip", ipStr, "program", conn.Program, "err", err)
			continue
		}

		if cachedFraudCheck != nil {
			if !cachedFraudCheck.ShouldKill {
				slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program, "reason", "cached-fraud-check")
				logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
				continue
			}

			logScanConnection(debug, ipStr, conn.Program, "vulnerable")
			slog.Warn("vulnerable connection detected", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program, "reason", "cached-fraud-check")
			if selectedMode == ModeWatch {
				slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
				continue
			}

			if err := hexwallStore.LogKill(ipStr, conn.PID, conn.Program); err != nil {
				slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
			}
			if err := somo.KillConnection(conn.PID); err != nil {
				slog.Error("failed to kill connection", "address", conn.RAddress, "pid", conn.PID, "err", err)
			} else {
				slog.Info("killed connection", "address", conn.RAddress)
			}
			continue
		}

		report, err := deghostClient.CheckIP(ctx, ipStr)
		if err != nil {
			slog.Error("deghost check failed", "ip", ipStr, "program", conn.Program, "err", err)
			continue
		}

		if report == nil {
			if err := hexwallStore.UpsertFraudCheck(ipStr, false); err != nil {
				slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
			}
			slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program, "reason", "403/private-or-reserved")
			logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
			continue
		}

		shouldKill := deghost.ShouldKill(report)
		if err := hexwallStore.UpsertFraudCheck(ipStr, shouldKill); err != nil {
			slog.Error("failed to cache fraud check", "ip", ipStr, "program", conn.Program, "err", err)
		}

		if !shouldKill {
			slog.Info("unrecognized but clean ip", "ip", ipStr, "program", conn.Program)
			logScanConnection(debug, ipStr, conn.Program, "unrecognized-clean")
			continue
		}

		logScanConnection(debug, ipStr, conn.Program, "vulnerable")

		slog.Warn("vulnerable connection detected", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
		if selectedMode == ModeWatch {
			slog.Warn("watch mode: would kill connection", "address", conn.RAddress, "pid", conn.PID, "program", conn.Program)
			continue
		}

		if err := hexwallStore.LogKill(ipStr, conn.PID, conn.Program); err != nil {
			slog.Error("failed to log kill", "address", conn.RAddress, "err", err)
		}
		if err := somo.KillConnection(conn.PID); err != nil {
			slog.Error("failed to kill connection", "address", conn.RAddress, "pid", conn.PID, "err", err)
		} else {
			slog.Info("killed connection", "address", conn.RAddress)
		}
	}
}
