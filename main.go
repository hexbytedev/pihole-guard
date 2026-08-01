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
	dbPath        string
	hexwallDBPath string
	zeekLogPath   string
	zeekNoticeLog string
	enableZeek    bool
	mode          string
	debug         bool
	showVersion   bool
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
	mode := flag.String("mode", monitor.ModeWatch, "monitor mode: watch (detect only) or enforce (kill + log)")
	debug := flag.Bool("debug", false, "enable verbose per-connection scan logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	cfg := &runConfig{
		dbPath:        strings.TrimSpace(*dbPath),
		hexwallDBPath: strings.TrimSpace(*hexwallDB),
		zeekLogPath:   strings.TrimSpace(*zeekLogPath),
		zeekNoticeLog: strings.TrimSpace(*zeekNoticeLog),
		enableZeek:    *enableZeek,
		mode:          strings.TrimSpace(*mode),
		debug:         *debug,
		showVersion:   *showVersion,
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

	deghostClient := deghost.NewClient(deghostBaseURL, deghostTimeout)

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
			monitor.RunScan(ctx, checker, hexwallStore, deghostClient, zeekClient, cfg.mode, cfg.debug)
		}
	}
}
