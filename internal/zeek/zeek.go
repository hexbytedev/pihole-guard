// Package zeek tails Zeek logs to extract SNI/domain data and DNS-bypass notices.
package zeek

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	tickInterval = 5 * time.Second
	entryExpiry  = 2 * time.Minute
)

// Config holds the configuration for the Zeek ssl.log tailer.
type Config struct {
	LogPath string
}

// Event is a parsed DNS bypass notice from Zeek.
type Event struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	DstPort   string
	SNI       string
}

type sniEntry struct {
	domain     string
	observedAt time.Time
}

// sslRecord is the subset of fields we extract from a Zeek SSL JSON log line.
type sslRecord struct {
	OrigH      string `json:"id.orig_h"`
	OrigP      any    `json:"id.orig_p"`
	RespH      string `json:"id.resp_h"`
	RespP      any    `json:"id.resp_p"`
	ServerName string `json:"server_name"`
}

// Client tails a Zeek ssl.log and maintains a short-lived in-memory cache
// mapping connection tuples to their observed SNI domain.
type Client struct {
	logPath string

	mu    sync.RWMutex
	cache map[string]sniEntry

	offset  int64
	pending []byte // bytes read past the last newline; held until the rest of the line arrives
	stopCh  chan struct{}
	done    chan struct{}
}

// NewClient opens the ssl.log at the configured path and starts a
// background goroutine that tails new JSON lines.
// If cfg is nil or LogPath is empty, it returns nil without error.
func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil || strings.TrimSpace(cfg.LogPath) == "" {
		return nil, nil
	}

	logPath := strings.TrimSpace(cfg.LogPath)

	// Verify the file exists and is readable before starting the tailer.
	f, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zeek ssl.log %s: %w", logPath, err)
	}
	fi, err := f.Stat()
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to stat zeek ssl.log %s: %w", logPath, err)
	}

	c := &Client{
		logPath: logPath,
		cache:   make(map[string]sniEntry),
		offset:  fi.Size(),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
	}

	go c.tailLoop(context.Background())

	slog.Info("zeek log watcher started", "path", logPath, "offset", c.offset)

	return c, nil
}

// Close stops the background tailer and waits for it to finish.
func (c *Client) Close() {
	if c == nil {
		return
	}
	close(c.stopCh)
	<-c.done
}

// Lookup returns the SNI domain observed for the given connection tuple,
// or ("", false) if no matching record exists in the cache.
func (c *Client) Lookup(localPort, remoteIP, remotePort string) (string, bool) {
	key := localPort + "|" + remoteIP + "|" + remotePort

	c.mu.RLock()
	entry, ok := c.cache[key]
	c.mu.RUnlock()

	if !ok {
		return "", false
	}

	if time.Since(entry.observedAt) > entryExpiry {
		return "", false
	}

	return entry.domain, true
}

// ParseNoticeLine parses a single Zeek notice JSON line into an Event.
func ParseNoticeLine(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, errors.New("empty notice line")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return Event{}, fmt.Errorf("parse notice line: %w", err)
	}

	event := Event{Timestamp: time.Now()}
	if ts, ok := payload["ts"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			event.Timestamp = parsed
		}
	}
	if ts, ok := payload["timestamp"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			event.Timestamp = parsed
		}
	}

	event.SrcIP = stringValue(payload["src_ip"], payload["src"], payload["id.orig_h"])
	event.DstIP = stringValue(payload["dst_ip"], payload["dst"], payload["id.resp_h"])
	event.DstPort = stringValue(payload["dst_port"], payload["p"], payload["id.resp_p"])
	event.SNI = stringValue(payload["sni"], payload["server_name"])

	if event.SrcIP == "" && event.DstIP == "" && event.SNI == "" {
		return Event{}, errors.New("notice line did not contain recognizable fields")
	}

	return event, nil
}

// WatchNoticeLog tails a Zeek notice log and emits parsed Events.
func WatchNoticeLog(ctx context.Context, path string, events chan<- Event) error {
	logPath := strings.TrimSpace(path)
	if ctx == nil || logPath == "" {
		return nil
	}

	var offset int64
	poller := time.NewTicker(2 * time.Second)
	defer poller.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poller.C:
			file, err := os.Open(logPath)
			if err != nil {
				slog.Debug("zeek: cannot open notice log", "path", logPath, "err", err)
				continue
			}

			fi, err := file.Stat()
			if err != nil {
				_ = file.Close()
				slog.Debug("zeek: cannot stat notice log", "path", logPath, "err", err)
				continue
			}

			if fi.Size() < offset {
				offset = 0
			}
			if fi.Size() > offset {
				if _, err := file.Seek(offset, io.SeekStart); err != nil {
					_ = file.Close()
					slog.Debug("zeek: seek notice log failed", "path", logPath, "err", err)
					continue
				}

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}

					event, err := ParseNoticeLine(line)
					if err != nil {
						continue
					}

					select {
					case events <- event:
					default:
					}
				}
				if err := scanner.Err(); err != nil {
					slog.Debug("zeek: notice log scan failed", "path", logPath, "err", err)
				}
			}
			_ = file.Close()
			offset = fi.Size()
		}
	}
}

func (c *Client) tailLoop(ctx context.Context) {
	defer close(c.done)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.processNewLines()
		}
	}
}

func (c *Client) processNewLines() {
	file, err := os.Open(c.logPath)
	if err != nil {
		slog.Debug("zeek: cannot open ssl.log", "path", c.logPath, "err", err)
		return
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		slog.Debug("zeek: cannot stat ssl.log", "path", c.logPath, "err", err)
		return
	}

	// File was likely rotated — reset to the beginning and drop any
	// partial line held over from the old file.
	if fi.Size() < c.offset {
		c.offset = 0
		c.pending = nil
	}

	if fi.Size() == c.offset {
		return
	}

	if _, err := file.Seek(c.offset, io.SeekStart); err != nil {
		slog.Debug("zeek: seek failed", "path", c.logPath, "err", err)
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		slog.Debug("zeek: read failed", "path", c.logPath, "err", err)
		return
	}

	// We've now consumed everything up to fi.Size() from the file, even
	// if the trailing bytes don't yet form a complete line — hold them in
	// pending rather than losing them, since Zeek may still be mid-write
	// on the last line when this tick fires.
	c.offset = fi.Size()

	buf := append(c.pending, data...)
	lastNewline := bytes.LastIndexByte(buf, '\n')
	if lastNewline == -1 {
		c.pending = buf
		return
	}

	complete := buf[:lastNewline]
	c.pending = append([]byte(nil), buf[lastNewline+1:]...)

	lines := strings.Split(string(complete), "\n")

	c.mu.Lock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var rec sslRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		if rec.ServerName == "" || rec.OrigH == "" || rec.RespH == "" {
			continue
		}

		origP := fmt.Sprint(rec.OrigP)
		respP := fmt.Sprint(rec.RespP)
		now := time.Now()
		entry := sniEntry{domain: rec.ServerName, observedAt: now}

		// Store both orientations so Lookup works regardless of which
		// side of the connection is the local endpoint.
		c.cache[origP+"|"+rec.RespH+"|"+respP] = entry
		c.cache[respP+"|"+rec.OrigH+"|"+origP] = entry
	}

	// Prune expired entries.
	cutoff := time.Now().Add(-entryExpiry)
	for k, v := range c.cache {
		if v.observedAt.Before(cutoff) {
			delete(c.cache, k)
		}
	}
	c.mu.Unlock()
}

func stringValue(values ...any) string {
	for _, value := range values {
		switch v := value.(type) {
		case string:
			return strings.TrimSpace(v)
		case fmt.Stringer:
			return strings.TrimSpace(v.String())
		case nil:
			continue
		default:
			return fmt.Sprint(v)
		}
	}
	return ""
}
