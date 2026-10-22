// Package proto is the protocol between termoak-server and termoak-netd
// (version 1, docs/NETWORKS.md §6): one Unix socket connection per request,
// one JSON line in, one JSON line out; after a successful dial the same
// connection carries the raw bytes of the TCP connection.
package proto

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
)

// Version is the protocol version this netd speaks.
const Version = 1

// MaxLine is the longest request line accepted (1 MiB).
const MaxLine = 1 << 20

// Error codes (netd → server). The server maps them to its own API errors
// and passes them on as `netd_code`.
const (
	CodeInvalid         = "invalid"          // malformed request
	CodeUnsupportedKind = "unsupported_kind" // this build cannot join the kind
	CodeNeedsAuth       = "needs_auth"       // the node waits for authorization
	CodeNetworkError    = "network_error"    // the network could not start
	CodeDialFailed      = "dial_failed"      // refused / unreachable inside the network
	CodeTimeout         = "timeout"          // timeout_ms passed
	CodeLimit           = "limit"            // netd resource limit
)

// Network states.
const (
	StateDown      = "down"
	StateStarting  = "starting"
	StateNeedsAuth = "needs_auth"
	StateUp        = "up"
	StateError     = "error"
)

// Why a node in StateNeedsAuth waits (Status.Auth, Error.Auth).
const (
	// AuthLogin: the node must be logged in (no auth key): open
	// Node.AuthURL (Tailscale login, Headscale registration).
	AuthLogin = "login"
	// AuthApproval: the node is logged in but an admin must approve it
	// (Tailscale device approval).
	AuthApproval = "approval"
)

// Request is one request line.
type Request struct {
	V         int    `json:"v"`
	Op        string `json:"op"`
	Network   *Spec  `json:"network,omitempty"`
	NetworkID string `json:"network_id,omitempty"`
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	TimeoutMs int64  `json:"timeout_ms,omitempty"`
	// Forget (down): the network was deleted. Besides stopping its node,
	// netd removes what it keeps of it (a persistent Tailscale node is
	// logged out and its state directory deleted).
	Forget bool `json:"forget,omitempty"`
}

// Spec is a whole network as the server sends it with every request that
// needs it: netd keeps no database.
type Spec struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Revision string `json:"revision"`
	// Config is the section of its kind (Network.wireguard, .tailscale...).
	Config json.RawMessage `json:"config"`
	// Secret holds the private keys: never logged.
	Secret  json.RawMessage `json:"secret"`
	VaultID string          `json:"vault_id,omitempty"`
}

var idPattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)

// ValidID tells whether a network id is acceptable (a UUID in practice).
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Validate checks the fields every backend needs.
func (s *Spec) Validate() error {
	if s == nil {
		return fmt.Errorf("the request has no network")
	}
	if !ValidID(s.ID) {
		return fmt.Errorf("invalid network id")
	}
	if s.Kind == "" {
		return fmt.Errorf("the network has no kind")
	}
	if len(s.Revision) > 128 {
		return fmt.Errorf("invalid revision")
	}
	return nil
}

// LogValue keeps secrets out of the logs (and the config: only ids).
func (s *Spec) LogValue() slog.Value {
	if s == nil {
		return slog.StringValue("<none>")
	}
	attrs := []slog.Attr{
		slog.String("id", s.ID),
		slog.String("kind", s.Kind),
		slog.String("revision", s.Revision),
	}
	if s.VaultID != "" {
		attrs = append(attrs, slog.String("vault", s.VaultID))
	}
	return slog.GroupValue(attrs...)
}

// String never prints the secret.
func (s *Spec) String() string {
	if s == nil {
		return "<none>"
	}
	return fmt.Sprintf("network %s (%s, rev %s)", s.ID, s.Kind, s.Revision)
}

// GoString never prints the secret (%#v).
func (s *Spec) GoString() string { return s.String() }

// Node is the server's node in a network.
type Node struct {
	Name      string   `json:"name,omitempty"`
	Addresses []string `json:"addresses"`
	PublicKey string   `json:"public_key,omitempty"`
	NodeID    string   `json:"node_id,omitempty"`
	AuthURL   string   `json:"auth_url,omitempty"`
	// DNSName: the node's MagicDNS name (Tailscale).
	DNSName string `json:"dns_name,omitempty"`
}

// Status of a network in netd.
type Status struct {
	NetworkID string `json:"network_id"`
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
	Node      *Node  `json:"node,omitempty"`
	Revision  string `json:"revision,omitempty"`
	// Since (ms) it is in this state.
	Since      int64 `json:"since,omitempty"`
	LastUsedAt int64 `json:"last_used_at,omitempty"`
	// Bytes of the tunnel (WireGuard: received from / sent to the peers).
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	// Latest handshake with any peer (ms; WireGuard).
	LastHandshakeAt int64 `json:"last_handshake_at,omitempty"`
	// Connections open through the network now.
	Streams int `json:"streams"`
	// Connections opened / failed since the network came up.
	Dials       uint64 `json:"dials"`
	DialsFailed uint64 `json:"dials_failed"`

	// Tailscale/Headscale (absent for WireGuard):
	// Auth tells why a needs_auth node waits: AuthLogin (open
	// Node.AuthURL) or AuthApproval (approve it in the admin console).
	Auth string `json:"auth,omitempty"`
	// ControlURL is the control server the node uses (Tailscale's when
	// the network has none).
	ControlURL string `json:"control_url,omitempty"`
	// Tailnet name and its MagicDNS suffix, once logged in.
	Tailnet        string `json:"tailnet,omitempty"`
	MagicDNSSuffix string `json:"magic_dns_suffix,omitempty"`
	// PeerCount: devices the node sees in the tailnet.
	PeerCount *int `json:"peer_count,omitempty"`
	// Ephemeral: the node leaves the tailnet when it stops.
	Ephemeral *bool `json:"ephemeral,omitempty"`
	// LastError: the latest error of the node (the control server refused
	// the auth key...), also while it retries.
	LastError string `json:"last_error,omitempty"`
}

// Peer is a device of the network ("import hosts").
type Peer struct {
	Name      string   `json:"name"`
	DNSName   string   `json:"dns_name,omitempty"`
	Addresses []string `json:"addresses"`
	OS        string   `json:"os,omitempty"`
	Online    *bool    `json:"online,omitempty"`
	LastSeen  int64    `json:"last_seen,omitempty"`
	PublicKey string   `json:"public_key,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	// Tailscale: ACL tags of the device and the subnets it routes for the
	// tailnet (exit routes left out).
	Tags   []string `json:"tags,omitempty"`
	Routes []string `json:"routes,omitempty"`
	// ID: the device's stable id in the tailnet (Tailscale).
	ID string `json:"id,omitempty"`
}

// Error is a refused request.
type Error struct {
	Code    string
	Message string
	// Auth (with CodeNeedsAuth): AuthLogin or AuthApproval.
	Auth string
}

func (e *Error) Error() string { return e.Message }

// Errorf builds an Error.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ErrorLine is the answer for an Error.
func ErrorLine(e *Error) map[string]any {
	line := map[string]any{"ok": false, "code": e.Code, "message": e.Message}
	if e.Auth != "" {
		line["auth"] = e.Auth
	}
	return line
}
