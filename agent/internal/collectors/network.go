package collectors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tecno-consultores/HostGrid/agent/internal/probe"
)

// ListeningSocket matches SPEC.md section 4.5 network listener schema.
type ListeningSocket struct {
	Proto     string `json:"proto"`
	LocalAddr string `json:"local_addr"`
	Port      int    `json:"port"`
	Process   string `json:"process"`
	PID       *int   `json:"pid,omitempty"`
}

// NetworkPayload wraps collected listening sockets.
type NetworkPayload struct {
	ListeningSockets []ListeningSocket `json:"listening_sockets"`
}

var (
	ssProcRe      = regexp.MustCompile(`"([^"]+)",pid=(\d+)`)
	netstatProcRe = regexp.MustCompile(`^(\d+)/(.+)$`)
)

// CollectNetwork inspects active listening sockets using ss -> netstat -> /proc/net/tcp fallback.
func CollectNetwork(ctx context.Context, env probe.Env) NetworkPayload {
	if env.RootDir == "" {
		env.RootDir = "/"
	}
	if env.LookPath != nil {
		if ssBin, err := env.LookPath("ss"); err == nil {
			// Omit -H so legacy iproute2 (Debian 8 / CentOS 7) works; ParseSSOutput skips headers.
			cmd := exec.CommandContext(ctx, ssBin, "-tulnp")
			if out, runErr := cmd.Output(); runErr == nil {
				return NetworkPayload{ListeningSockets: ParseSSOutput(bytes.NewReader(out))}
			}
		}
		if netstatBin, err := env.LookPath("netstat"); err == nil {
			cmd := exec.CommandContext(ctx, netstatBin, "-tulnp")
			if out, runErr := cmd.Output(); runErr == nil {
				return NetworkPayload{ListeningSockets: ParseNetstatOutput(bytes.NewReader(out))}
			}
		}
	}

	var sockets []ListeningSocket
	if f, err := os.Open(filepath.Join(env.RootDir, "proc/net/tcp")); err == nil {
		sockets = append(sockets, ParseProcNetTCP(f, "tcp")...)
		_ = f.Close()
	}
	if f6, err := os.Open(filepath.Join(env.RootDir, "proc/net/tcp6")); err == nil {
		sockets = append(sockets, ParseProcNetTCP(f6, "tcp6")...)
		_ = f6.Close()
	}
	if sockets == nil {
		sockets = []ListeningSocket{}
	}
	return NetworkPayload{ListeningSockets: sockets}
}

// ParseSSOutput parses output from `ss -tulnpH`.
func ParseSSOutput(r io.Reader) []ListeningSocket {
	scanner := bufio.NewScanner(r)
	sockets := []ListeningSocket{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		proto := normalizeProto(fields[0])
		if proto == "" {
			continue
		}
		addr, port, ok := splitHostPort(fields[4])
		if !ok {
			continue
		}
		var proc string
		var pidPtr *int
		if len(fields) >= 7 {
			rest := strings.Join(fields[6:], " ")
			if m := ssProcRe.FindStringSubmatch(rest); len(m) == 3 {
				proc = m[1]
				if pidVal, err := strconv.Atoi(m[2]); err == nil {
					pidPtr = &pidVal
				}
			}
		}
		sockets = append(sockets, ListeningSocket{
			Proto:     proto,
			LocalAddr: addr,
			Port:      port,
			Process:   proc,
			PID:       pidPtr,
		})
	}
	return sockets
}

// ParseNetstatOutput parses output from `netstat -tulnp`.
func ParseNetstatOutput(r io.Reader) []ListeningSocket {
	scanner := bufio.NewScanner(r)
	sockets := []ListeningSocket{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		proto := normalizeProto(fields[0])
		if proto == "" {
			continue
		}
		addr, port, ok := splitHostPort(fields[3])
		if !ok {
			continue
		}
		var proc string
		var pidPtr *int
		for _, candidate := range fields[5:] {
			if m := netstatProcRe.FindStringSubmatch(candidate); len(m) == 3 {
				if pidVal, err := strconv.Atoi(m[1]); err == nil {
					pidPtr = &pidVal
				}
				proc = strings.TrimRight(m[2], ":")
				break
			}
		}
		sockets = append(sockets, ListeningSocket{
			Proto:     proto,
			LocalAddr: addr,
			Port:      port,
			Process:   proc,
			PID:       pidPtr,
		})
	}
	return sockets
}

// ParseProcNetTCP decodes Linux /proc/net/tcp and /proc/net/tcp6 LISTEN (0A) sockets.
func ParseProcNetTCP(r io.Reader, proto string) []ListeningSocket {
	scanner := bufio.NewScanner(r)
	sockets := []ListeningSocket{}
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		parts := strings.SplitN(fields[1], ":", 2)
		if len(parts) != 2 {
			continue
		}
		port64, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}
		ipStr, ok := decodeProcHexIP(parts[0])
		if !ok {
			continue
		}
		sockets = append(sockets, ListeningSocket{
			Proto:     proto,
			LocalAddr: ipStr,
			Port:      int(port64),
			Process:   "",
		})
	}
	return sockets
}

func decodeProcHexIP(hexAddr string) (string, bool) {
	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return "", false
	}
	if len(raw) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", raw[3], raw[2], raw[1], raw[0]), true
	}
	if len(raw) == 16 {
		ip := make(net.IP, 16)
		for word := 0; word < 4; word++ {
			base := word * 4
			ip[base] = raw[base+3]
			ip[base+1] = raw[base+2]
			ip[base+2] = raw[base+1]
			ip[base+3] = raw[base]
		}
		return ip.String(), true
	}
	return "", false
}

func normalizeProto(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tcp", "tcp6", "udp", "udp6":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func splitHostPort(endpoint string) (string, int, bool) {
	idx := strings.LastIndexByte(endpoint, ':')
	if idx < 0 {
		return "", 0, false
	}
	addr := strings.TrimSpace(endpoint[:idx])
	portStr := strings.TrimSpace(endpoint[idx+1:])
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, false
	}
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	if pct := strings.IndexByte(addr, '%'); pct >= 0 {
		addr = addr[:pct]
	}
	if addr == "*" || addr == "" {
		addr = "0.0.0.0"
	}
	return addr, port, true
}
