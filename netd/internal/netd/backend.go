package netd

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"sync"

	"github.com/TermoakSSH/server/netd/internal/proto"
)

// Backend joins networks of one kind (wireguard, tailscale, zerotier).
//
// WireGuard is always built in. Tailscale (tsnet) and ZeroTier (libzt) will
// be added behind build tags: a file with `//go:build tailscale` in
// cmd/termoak-netd calls Register("tailscale", …) from its init. Without
// it, networks of that kind answer `unsupported_kind` and `hello` does not
// list the kind.
type Backend interface {
	// Start brings a node up for spec. It must not block for long: a node
	// that needs time (authorization, control server) reports it in Info.
	Start(ctx context.Context, spec *proto.Spec, log *slog.Logger) (Node, error)
}

// Node is one network's isolated node: its own user-space stack, never the
// host's kernel network stack, never shared with another network.
type Node interface {
	// Dial opens a TCP connection to host:port inside the network.
	Dial(ctx context.Context, host string, port int) (net.Conn, error)
	// Info is the node as Status shows it (state may be needs_auth...).
	Info() NodeInfo
	// Peers are the devices of the network.
	Peers(ctx context.Context) ([]proto.Peer, error)
	// Close takes the node down (its connections end).
	Close() error
}

// NodeInfo is what a node reports for Status.
type NodeInfo struct {
	// State: up, needs_auth or error (starting is the manager's).
	State           string
	Message         string
	Node            *proto.Node
	RxBytes         uint64
	TxBytes         uint64
	LastHandshakeAt int64
}

var (
	backendsMu sync.RWMutex
	backends   = map[string]Backend{}
)

// Register makes a kind available (from an init function).
func Register(kind string, b Backend) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	backends[kind] = b
}

func backendFor(kind string) (Backend, bool) {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	b, ok := backends[kind]
	return b, ok
}

// Kinds this build can join (for hello).
func Kinds() []string {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	out := make([]string, 0, len(backends))
	for k := range backends {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// plannedKinds are known kinds this build may lack (a clean
// unsupported_kind instead of "unknown kind").
var plannedKinds = map[string]string{
	"tailscale": "this termoak-netd cannot join Tailscale or Headscale networks yet (it was built without tsnet)",
	"zerotier":  "this termoak-netd cannot join ZeroTier networks (it was built without libzt)",
}
