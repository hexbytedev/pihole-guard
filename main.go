// Package main wires together Pi-hole discovery, cache refreshes, and connection monitoring.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hexbytedev/hexwall/internal/deghost"
	"github.com/hexbytedev/hexwall/internal/detector"
	"github.com/hexbytedev/hexwall/internal/monitor"
	"github.com/hexbytedev/hexwall/internal/pihole"
	"github.com/hexbytedev/hexwall/internal/somo"
	"github.com/hexbytedev/hexwall/internal/store"
	"github.com/hexbytedev/hexwall/internal/zeek"
)

const (
	deghostBaseURL         = "https://deghostapi.hexbyte.dev"
	deghostTimeout         = 5 * time.Second
	trustedRefreshInterval = 30 * time.Second
	connectionScanInterval = 10 * time.Second
)

var (
	version  = "dev"
	platform = runtime.GOOS + "/" + runtime.GOARCH
)

type runConfig struct {
	dbPath              string
	hexwallDBPath       string
	zeekLogPath         string
	zeekNoticeLog       string
	enableZeek          bool
	enableDeghostIP     bool
	enableDeghostDomain bool
	mode                string
	debug               bool
	showVersion         bool
}

func main() {
	os.Exit(run())
}

func parseFlags() (*runConfig, error) {
	dbPath := flag.String("db", "", "path to pihole-FTL.db (auto-detected if not set)")
	hexwallDB := flag.String("hexwall-db", "./hexwall.db", "path to local hexwall database")
	zeekLogPath := flag.String("zeek-log", "", "path to zeek ssl.log for SNI-based domain verification (empty to skip)")
	zeekNoticeLog := flag.String("zeek-notice-log", "/opt/zeek/logs/current/notice.log", "path to Zeek notice.log for DNS-bypass alerts")
	enableZeek := flag.Bool("enable-zeek", false, "enable Zeek-based DNS-bypass detection")
	enableDeghostIP := flag.Bool("enable-deghost-ip", true, "enable third-party IP reputation checks on the IP-only fallback path")
	enableDeghostDomain := flag.Bool("enable-deghost-domain", true, "enable third-party domain reputation checks at rung 6")
	mode := flag.String("mode", monitor.ModeWatch, "monitor mode: watch (detect only) or enforce (kill + log)")
	debug := flag.Bool("debug", false, "enable debug-level logging, including verbose per-connection scan logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	cfg := &runConfig{
		dbPath:              strings.TrimSpace(*dbPath),
		hexwallDBPath:       strings.TrimSpace(*hexwallDB),
		zeekLogPath:         strings.TrimSpace(*zeekLogPath),
		zeekNoticeLog:       strings.TrimSpace(*zeekNoticeLog),
		enableZeek:          *enableZeek,
		enableDeghostIP:     *enableDeghostIP,
		enableDeghostDomain: *enableDeghostDomain,
		mode:                strings.TrimSpace(*mode),
		debug:               *debug,
		showVersion:         *showVersion,
	}

	if cfg.showVersion {
		return cfg, nil
	}

	selectedMode := strings.ToLower(cfg.mode)
	if selectedMode != monitor.ModeWatch && selectedMode != monitor.ModeEnforce {
		return nil, fmt.Errorf("invalid --mode value %q: allowed %q or %q", cfg.mode, monitor.ModeWatch, monitor.ModeEnforce)
	}
	cfg.mode = selectedMode

	if cfg.hexwallDBPath == "" {
		return nil, fmt.Errorf("invalid --hexwall-db value %q", *hexwallDB)
	}

	return cfg, nil
}

func run() int {
	cfg, err := parseFlags()
	if err != nil {
		slog.Error(err.Error())
		return 1
	}

	if cfg == nil {
		return 1
	}

	// Install the log handler first so every later slog call honours --debug.
	logLevel := slog.LevelInfo
	if cfg.debug {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	if cfg.showVersion {
		fmt.Printf("%s (%s)\n", version, platform)
		return 0
	}

	// Cancel background work cleanly on Ctrl+C.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Verify that somo is available before starting any monitoring.
	if err := somo.CheckInstalled(); err != nil {
		slog.Error("somo is not installed", "err", err, "tip", "install somo from https://github.com/theopfr/somo")
		return 1
	}

	// 2. Resolve the Pi-hole database path from --db or auto-detection.
	if cfg.dbPath == "" {
		detected, err := detector.FindDBPath()
		if err != nil {
			slog.Error("could not find pi-hole installation", "err", err)
			return 1
		}

		cfg.dbPath = detected
		slog.Info("pi-hole database auto-detected", "path", cfg.dbPath)
	}

	// 3. Open the Pi-hole database in read-only mode.
	checker, err := pihole.NewChecker(&pihole.Config{DBPath: cfg.dbPath})
	if err != nil {
		slog.Error("failed to open pi-hole database", "path", cfg.dbPath, "err", err)
		return 1
	}
	defer func() {
		if err := checker.Close(); err != nil {
			slog.Error("failed to close pi-hole database", "err", err)
		}
	}()

	// 3b. Log policy list summary from gravity.db.
	if counts, err := checker.PolicyCounts(); err != nil {
		slog.Warn("failed to read pi-hole policy counts", "err", err)
	} else if counts != nil {
		slog.Info("pihole policy lists loaded",
			"allow", counts["vw_allowlist"],
			"deny", counts["vw_denylist"],
			"gravity", counts["vw_gravity"],
			"regex_allow", counts["vw_regex_allowlist"],
			"regex_deny", counts["vw_regex_denylist"])
		if counts["vw_gravity"] == 0 {
			slog.Warn("pi-hole gravity list is empty; blocklist may be broken or not yet downloaded")
		}
	}

	// 4. Open the local hexwall database, creating it if needed.
	hexwallStore, err := store.NewStore(cfg.hexwallDBPath)
	if err != nil {
		slog.Error("failed to open hexwall database", "path", cfg.hexwallDBPath, "err", err)
		return 1
	}
	defer func() {
		if err := hexwallStore.Close(); err != nil {
			slog.Error("failed to close hexwall database", "err", err)
		}
	}()

	slog.Info("hexwall database ready", "path", cfg.hexwallDBPath)

	// 4a. Prune stale rows from prior runs at startup.
	if result, err := hexwallStore.Prune(); err != nil {
		slog.Warn("initial prune failed", "err", err)
	} else if result != nil && (result.AllowedIPDomains+result.SNIObservations+result.IPObservations+result.KilledConnections+result.ZeekAlerts) > 0 {
		slog.Info("pruned stale rows",
			"allowed_ip_domains", result.AllowedIPDomains,
			"sni_observations", result.SNIObservations,
			"ip_observations", result.IPObservations,
			"killed_connections", result.KilledConnections,
			"zeek_alerts", result.ZeekAlerts)
	}

	// 4b. Start the Zeek ssl.log tailer when a path is provided.
	var zeekClient *zeek.Client
	if cfg.zeekLogPath != "" {
		zc, err := zeek.NewClient(&zeek.Config{
			LogPath: cfg.zeekLogPath,
		})

		if err != nil {
			slog.Error("failed to start zeek log watcher", "path", cfg.zeekLogPath, "err", err)
			return 1
		}

		defer zc.Close()
		zeekClient = zc
	}

	var zeekEvents = make(chan zeek.Event, 100)
	if cfg.enableZeek && cfg.zeekNoticeLog != "" {
		go func() {
			if err := zeek.WatchNoticeLog(ctx, cfg.zeekNoticeLog, zeekEvents); err != nil {
				slog.Error("zeek notice watcher stopped", "path", cfg.zeekNoticeLog, "err", err)
			}
		}()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case event := <-zeekEvents:
					monitor.HandleZeekEvent(checker, hexwallStore, cfg.mode, event)
				}
			}
		}()
	}

	// deghost is opt-in: it sends every unrecognized domain to a third-party API,
	// which is a real privacy cost. Only construct the client when at least one check is enabled.
	var deghostClient *deghost.Client
	if cfg.enableDeghostIP || cfg.enableDeghostDomain {
		deghostClient = deghost.NewClient(deghostBaseURL, deghostTimeout)
	} else {
		slog.Info("deghost disabled; unrecognized connections will not be escalated to third-party API")
	}

	if cfg.mode == monitor.ModeEnforce && cfg.enableDeghostIP {
		slog.Warn("enforce mode with IP deghost enabled: an external reputation verdict can now terminate a local process; shared cloud provider ranges are known to produce false positives on such feeds")
	}

	// 5. Refresh trusted IPs before starting the monitor so the first tick does not kill legitimate connections.
	cache := pihole.NewIPCache(checker, hexwallStore)
	cache.Refresh(ctx)

	// 6. Keep the trusted-IP cache fresh in the background without re-running the startup refresh immediately.
	go func() {
		ticker := time.NewTicker(trustedRefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cache.Refresh(ctx)
			}
		}
	}()

	// 6b. Periodically prune stale rows from the hexwall database.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if result, err := hexwallStore.Prune(); err != nil {
					slog.Warn("periodic prune failed", "err", err)
				} else if result != nil && (result.AllowedIPDomains+result.SNIObservations+result.IPObservations+result.KilledConnections+result.ZeekAlerts) > 0 {
					slog.Info("pruned stale rows",
						"allowed_ip_domains", result.AllowedIPDomains,
						"sni_observations", result.SNIObservations,
						"ip_observations", result.IPObservations,
						"killed_connections", result.KilledConnections,
						"zeek_alerts", result.ZeekAlerts)
				}
			}
		}
	}()

	fmt.Println("Starting network monitor...")
	fmt.Printf("> Connections will be checked every %s in %s mode.\n", connectionScanInterval, cfg.mode)
	if cfg.debug {
		fmt.Println("> Debug logging is enabled for every scanned connection.")
	}

	// 7. Scan connections every 10 seconds.
	ticker := time.NewTicker(connectionScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return 0
		case <-ticker.C:
			monitor.RunScan(ctx, checker, hexwallStore, deghostClient, cfg.enableDeghostIP, cfg.enableDeghostDomain, zeekClient, cfg.mode, cfg.debug)
		}
	}
}
