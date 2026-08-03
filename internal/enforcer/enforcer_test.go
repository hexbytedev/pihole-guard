package enforcer

import (
	"os"
	"strings"
	"testing"
)

func TestKillProcessRefusesPIDZero(t *testing.T) {
	t.Parallel()

	err := KillProcess(0, "curl", "1.2.3.4:443")
	if err == nil {
		t.Fatal("KillProcess(0) = nil, want error")
	}
}

func TestKillProcessRefusesNegativePID(t *testing.T) {
	t.Parallel()

	err := KillProcess(-1, "curl", "1.2.3.4:443")
	if err == nil {
		t.Fatal("KillProcess(-1) = nil, want error")
	}
}

func TestKillProcessRefusesPIDOne(t *testing.T) {
	t.Parallel()

	err := KillProcess(1, "systemd", "1.2.3.4:443")
	if err == nil {
		t.Fatal("KillProcess(1) = nil, want error for init")
	}
}

func TestKillProcessRefusesOwnPID(t *testing.T) {
	t.Parallel()

	err := KillProcess(os.Getpid(), "test", "1.2.3.4:443")
	if err == nil {
		t.Fatal("KillProcess(own PID) = nil, want error")
	}
}

func TestKillProcessRefusesProtectedPrograms(t *testing.T) {
	t.Parallel()

	protected := []string{
		"systemd", "init", "sshd", "NetworkManager",
		"systemd-resolved", "systemd-networkd", "dbus-daemon",
		"containerd", "dockerd",
	}

	for _, prog := range protected {
		// Use a non-init, non-own PID that we know exists won't be matched
		// by the other guards. PID 2 is usually kthreadd on Linux.
		err := KillProcess(2, prog, "1.2.3.4:443")
		if err == nil {
			t.Errorf("KillProcess(2, %q) = nil, want error for protected program", prog)
			continue
		}
		if !strings.Contains(err.Error(), "protected") {
			t.Errorf("KillProcess(2, %q) error = %q, want it to mention 'protected'", prog, err)
		}
	}
}

func TestKillProcessCaseInsensitiveProtectedMatch(t *testing.T) {
	t.Parallel()

	cases := []string{"SSHD", "SystemD", "NETWORKMANAGER", "containerd", "DockerD"}
	for _, prog := range cases {
		err := KillProcess(2, prog, "1.2.3.4:443")
		if err == nil {
			t.Errorf("KillProcess(2, %q) = nil, want error for case-insensitive protected match", prog)
			continue
		}
		if !strings.Contains(err.Error(), "protected") {
			t.Errorf("KillProcess(2, %q) error = %q, want it to mention 'protected'", prog, err)
		}
	}
}

func TestParsePIDValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  int
	}{
		{"1234", 1234},
		{"  5678  ", 5678},
		{"0", 0},
		{"1", 1},
	}

	for _, tt := range tests {
		got, err := ParsePID(tt.input)
		if err != nil {
			t.Errorf("ParsePID(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParsePID(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParsePIDInvalid(t *testing.T) {
	t.Parallel()

	tests := []string{"", "-", "abc", "12.34", "12ab"}
	for _, input := range tests {
		_, err := ParsePID(input)
		if err == nil {
			t.Errorf("ParsePID(%q) = nil, want error", input)
		}
	}
}

func TestIsProtected(t *testing.T) {
	t.Parallel()

	if !isProtected("sshd") {
		t.Error("isProtected(\"sshd\") = false, want true")
	}
	if !isProtected("SSHD") {
		t.Error("isProtected(\"SSHD\") = false, want true (case-insensitive)")
	}
	if !isProtected("SystemD") {
		t.Error("isProtected(\"SystemD\") = false, want true (case-insensitive)")
	}
	if isProtected("curl") {
		t.Error("isProtected(\"curl\") = true, want false")
	}
	if isProtected("") {
		t.Error("isProtected(\"\") = true, want false")
	}
}

func TestIsProtectedMixedCaseAllEntries(t *testing.T) {
	t.Parallel()

	for name := range protectedPrograms {
		// Construct a mixed-case variant: uppercase first char + lowercase rest.
		mixed := strings.ToUpper(name[:1]) + name[1:]
		if !isProtected(mixed) {
			t.Errorf("isProtected(%q) = false, want true for mixed-case spelling of protected program", mixed)
		}
	}
}
