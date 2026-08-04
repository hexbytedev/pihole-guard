// Package enforcer terminates processes that hold blocked connections.
//
// STOPGAP: this is deliberately coarser than intended. The goal is to terminate a single
// connection; killing the owning process takes down every other connection it holds too.
// It exists because somo offers no non-interactive per-connection kill. Replace with
// `ss -K dst <ip> dport <port>` (requires CONFIG_INET_DIAG_DESTROY) when that work is done.
package enforcer

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// protectedPrograms is the default set of programs that must never be killed.
// All keys MUST be lowercase: isProtected lowercases the input before lookup.
var protectedPrograms = map[string]bool{
	"systemd":          true,
	"init":             true,
	"sshd":             true,
	"networkmanager":   true,
	"systemd-resolved": true,
	"systemd-networkd": true,
	"dbus-daemon":      true,
	"containerd":       true,
	"dockerd":          true,
}

// SetProtectedPrograms replaces the default protected-program set.
// Keys are normalized to lowercase on entry because isProtected lowercases
// its input, so stored keys must match for the lookup to work.
func SetProtectedPrograms(programs map[string]bool) {
	normalized := make(map[string]bool, len(programs))
	for k, v := range programs {
		normalized[strings.ToLower(k)] = v
	}
	protectedPrograms = normalized
}

// isProtected reports whether the program name (case-insensitive) is in the protected set.
func isProtected(name string) bool {
	lower := strings.ToLower(name)
	return protectedPrograms[lower]
}

// KillProcess terminates the process holding a connection.
//
// Guardrails:
//   - Refuses PID 1 (init).
//   - Refuses hexwall's own PID.
//   - Refuses any PID <= 0.
//   - Refuses protected programs (case-insensitive match).
//   - Sends SIGTERM first, waits a grace period, then SIGKILL if still alive.
func KillProcess(pid int, program string, remoteAddr string) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID %d", pid)
	}

	if pid == 1 {
		return fmt.Errorf("refusing to signal init (PID 1)")
	}

	if pid == os.Getpid() {
		return fmt.Errorf("refusing to signal own process (PID %d)", pid)
	}

	if isProtected(program) {
		return fmt.Errorf("refusing to kill protected program %q (PID %d)", program, pid)
	}

	slog.Warn("killing connection", "pid", pid, "program", program, "address", remoteAddr)

	// SIGTERM first — allows graceful shutdown.
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to PID %d: %w", pid, err)
	}

	// Grace period: wait up to 2 seconds for the process to exit.
	time.Sleep(2 * time.Second)

	// Check whether the process still exists.
	if err := syscall.Kill(pid, 0); err != nil {
		// Process is gone — SIGTERM worked.
		slog.Info("process terminated by SIGTERM", "pid", pid, "program", program)
		return nil
	}

	// Process still alive — escalate to SIGKILL.
	slog.Warn("process survived SIGTERM, sending SIGKILL", "pid", pid, "program", program)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("send SIGKILL to PID %d: %w", pid, err)
	}

	return nil
}

// ParsePID converts a string PID to int, returning an error for invalid input.
func ParsePID(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, fmt.Errorf("empty or dash PID %q", s)
	}

	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid PID %q: %w", s, err)
	}

	return pid, nil
}
