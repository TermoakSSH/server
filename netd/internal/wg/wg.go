// Package wg joins WireGuard networks fully in user space: wireguard-go
// with gVisor's netstack (no TUN device, no root, no routes). Every network
// is its own device and its own TCP/IP stack: nothing is shared between
// networks, and the host's kernel stack only carries the encrypted UDP
// packets to the peers' endpoints.
package wg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/proto"
)

// DefaultMTU of the tunnel (what wg-quick uses).
const DefaultMTU = 1420

// Config is Network.wireguard (the non-secret part).
type Config struct {
	Addresses []string `json:"addresses"`
	DNS       []string `json:"dns"`
	MTU       *int     `json:"mtu"`
	Peers     []Peer   `json:"peers"`
	PublicKey *string  `json:"public_key"`
}

// Peer is a WireGuard peer of the network.
type Peer struct {
	PublicKey           string   `json:"public_key"`
	Endpoint            *string  `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive *int     `json:"persistent_keepalive"`
}

// Secret is NetworkSecret (the WireGuard fields).
type Secret struct {
	PrivateKey   string `json:"private_key"`
	PresharedKey string `json:"preshared_key"`
}

// Key is a WireGuard key (Curve25519, 32 bytes).
type Key [32]byte

// ParseKey reads a base64 key (what wg and the apps show).
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return k, errors.New("a WireGuard key is 32 bytes in base64 (44 characters)")
	}
	copy(k[:], b)
	return k, nil
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }
func (k Key) hex() string    { return hex.EncodeToString(k[:]) }

// PublicKey of a private key.
func (k Key) PublicKey() Key {
	var pub Key
	out, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err == nil {
		copy(pub[:], out)
	}
	return pub
}

// plan is a parsed, validated configuration.
type plan struct {
	addresses []netip.Addr
	prefixes  []netip.Prefix // the node's own addresses with their prefix
	dns       []netip.Addr
	search    []string
	mtu       int
	private   Key
	psk       *Key
	peers     []peerPlan
}

type peerPlan struct {
	public    Key
	endpoint  string // as configured
	resolved  netip.AddrPort
	allowed   []netip.Prefix
	keepalive int
}

// parse validates the spec. Endpoint names are resolved later (Start).
func parse(spec *proto.Spec) (*plan, error) {
	var cfg Config
	if len(spec.Config) > 0 && string(spec.Config) != "null" {
		if err := json.Unmarshal(spec.Config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid WireGuard configuration: %w", err)
		}
	}
	var sec Secret
	if len(spec.Secret) > 0 && string(spec.Secret) != "null" {
		if err := json.Unmarshal(spec.Secret, &sec); err != nil {
			return nil, errors.New("invalid WireGuard secret")
		}
	}
	p := &plan{mtu: DefaultMTU}
	if strings.TrimSpace(sec.PrivateKey) == "" {
		return nil, errors.New("the network has no private key: generate one or paste the interface's PrivateKey")
	}
	k, err := ParseKey(sec.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	p.private = k
	if strings.TrimSpace(sec.PresharedKey) != "" {
		psk, err := ParseKey(sec.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("invalid preshared key: %w", err)
		}
		p.psk = &psk
	}
	for _, a := range cfg.Addresses {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			addr, err2 := netip.ParseAddr(a)
			if err2 != nil {
				return nil, fmt.Errorf("invalid address %q (expected 10.0.0.2/32 or 10.0.0.2)", a)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		p.addresses = append(p.addresses, pfx.Addr())
		p.prefixes = append(p.prefixes, pfx)
	}
	if len(p.addresses) == 0 {
		return nil, errors.New("the network has no address for the server (the interface's Address, e.g. 10.0.0.2/32)")
	}
	for _, d := range cfg.DNS {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if addr, err := netip.ParseAddr(d); err == nil {
			p.dns = append(p.dns, addr)
		} else {
			// wg-quick also takes search domains in DNS =.
			p.search = append(p.search, strings.Trim(d, "."))
		}
	}
	if cfg.MTU != nil && *cfg.MTU > 0 {
		if *cfg.MTU < 576 || *cfg.MTU > 9000 {
			return nil, fmt.Errorf("invalid MTU %d", *cfg.MTU)
		}
		p.mtu = *cfg.MTU
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("the network has no peers")
	}
	for i, pc := range cfg.Peers {
		pub, err := ParseKey(pc.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %d: invalid public key: %w", i+1, err)
		}
		pp := peerPlan{public: pub}
		if pc.Endpoint != nil {
			pp.endpoint = strings.TrimSpace(*pc.Endpoint)
		}
		for _, a := range pc.AllowedIPs {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			pfx, err := netip.ParsePrefix(a)
			if err != nil {
				addr, err2 := netip.ParseAddr(a)
				if err2 != nil {
					return nil, fmt.Errorf("peer %d: invalid allowed IP %q", i+1, a)
				}
				pfx = netip.PrefixFrom(addr, addr.BitLen())
			}
			pp.allowed = append(pp.allowed, pfx.Masked())
		}
		if pc.PersistentKeepalive != nil && *pc.PersistentKeepalive > 0 {
			if *pc.PersistentKeepalive > 65535 {
				return nil, fmt.Errorf("peer %d: invalid persistent keepalive", i+1)
			}
			pp.keepalive = *pc.PersistentKeepalive
		}
		p.peers = append(p.peers, pp)
	}
	return p, nil
}

// resolveEndpoints turns endpoint names into addresses (with the host's
// resolver: the endpoint is outside the network).
func (p *plan) resolveEndpoints(ctx context.Context) error {
	for i := range p.peers {
		pp := &p.peers[i]
		if pp.endpoint == "" {
			continue
		}
		host, port, err := net.SplitHostPort(pp.endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint %q (expected host:port)", pp.endpoint)
		}
		pn, err := strconv.ParseUint(port, 10, 16)
		if err != nil || pn == 0 {
			return fmt.Errorf("invalid endpoint port in %q", pp.endpoint)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(addrs) == 0 {
				return fmt.Errorf("could not resolve the endpoint %s: %v", host, err)
			}
			addr = addrs[0]
			for _, a := range addrs {
				if a.Is4() { // IPv4 first: more often reachable
					addr = a
					break
				}
			}
		}
		pp.resolved = netip.AddrPortFrom(addr.Unmap(), uint16(pn))
	}
	return nil
}

// uapi is the wireguard-go configuration.
func (p *plan) uapi() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\n", p.private.hex())
	for _, pp := range p.peers {
		fmt.Fprintf(&b, "public_key=%s\n", pp.public.hex())
		if p.psk != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", p.psk.hex())
		}
		if pp.resolved.IsValid() {
			fmt.Fprintf(&b, "endpoint=%s\n", pp.resolved)
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", pp.keepalive)
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range pp.allowed {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String()
}

// Backend is the WireGuard backend.
type Backend struct {
	// Bind makes the UDP transport (default: conn.NewDefaultBind). Tests
	// can bind to loopback.
	Bind func() conn.Bind
}

// Node is a running WireGuard network.
type Node struct {
	plan *plan
	dev  *device.Device
	tnet *netstack.Net
	log  *slog.Logger
	once sync.Once
}

// Start brings the network up: a wireguard-go device over its own netstack.
// It does not wait for a handshake (the first packet starts one).
func (b *Backend) Start(ctx context.Context, spec *proto.Spec, log *slog.Logger) (_ netd.Node, err error) {
	p, err := parse(spec)
	if err != nil {
		return nil, err
	}
	if err := p.resolveEndpoints(ctx); err != nil {
		return nil, err
	}
	tunDev, tnet, err := netstack.CreateNetTUN(p.addresses, p.dns, p.mtu)
	if err != nil {
		return nil, fmt.Errorf("could not create the network stack: %w", err)
	}
	bind := conn.NewDefaultBind()
	if b != nil && b.Bind != nil {
		bind = b.Bind()
	}
	dev := device.NewDevice(tunDev, bind, &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug("wireguard: " + fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			log.Warn("wireguard: " + fmt.Sprintf(format, args...))
		},
	})
	defer func() {
		if err != nil {
			dev.Close()
		}
	}()
	if err := dev.IpcSet(p.uapi()); err != nil {
		return nil, fmt.Errorf("invalid WireGuard configuration: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("could not bring the WireGuard device up: %w", err)
	}
	n := &Node{plan: p, dev: dev, tnet: tnet, log: log}
	log.Info("wireguard device up", "addresses", p.addresses, "peers", len(p.peers),
		"dns", len(p.dns), "mtu", p.mtu, "public_key", p.private.PublicKey().String())
	return n, nil
}

// Close takes the device (and its stack) down.
func (n *Node) Close() error {
	n.once.Do(func() { n.dev.Close() })
	return nil
}

// routed tells whether some peer's allowed IPs contain addr.
func (n *Node) routed(addr netip.Addr) bool {
	for _, pp := range n.plan.peers {
		for _, a := range pp.allowed {
			if a.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// resolve finds the addresses of host: an IP as is; a name with the
// network's DNS servers (through the tunnel) when the network has them,
// otherwise with the system resolver (/etc/hosts, the host's DNS). Only
// addresses some peer routes are kept.
func (n *Node) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		a = a.Unmap()
		if !n.routed(a) {
			return nil, proto.Errorf(proto.CodeDialFailed, "%s is outside the network (no peer's allowed IPs contain it)", a)
		}
		return []netip.Addr{a}, nil
	}
	var names []string
	if len(n.plan.search) > 0 && !strings.Contains(host, ".") {
		for _, s := range n.plan.search {
			names = append(names, host+"."+s)
		}
	}
	names = append(names, host)
	var found []netip.Addr
	var lastErr error
	for _, name := range names {
		var addrs []netip.Addr
		if len(n.plan.dns) > 0 {
			list, err := n.tnet.LookupContextHost(ctx, name)
			if err != nil {
				lastErr = err
				continue
			}
			for _, s := range list {
				if a, err := netip.ParseAddr(s); err == nil {
					addrs = append(addrs, a.Unmap())
				}
			}
		} else {
			list, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
			if err != nil {
				lastErr = err
				continue
			}
			for _, a := range list {
				addrs = append(addrs, a.Unmap())
			}
		}
		if len(addrs) > 0 {
			found = addrs
			break
		}
	}
	if len(found) == 0 {
		where := "the system resolver (the network has no DNS servers)"
		if len(n.plan.dns) > 0 {
			where = "the network's DNS servers"
		}
		if lastErr != nil {
			return nil, proto.Errorf(proto.CodeDialFailed, "could not resolve %s with %s: %s", host, where, lastErr)
		}
		return nil, proto.Errorf(proto.CodeDialFailed, "could not resolve %s with %s", host, where)
	}
	var routed []netip.Addr
	for _, a := range found {
		if n.routed(a) {
			routed = append(routed, a)
		}
	}
	if len(routed) == 0 {
		return nil, proto.Errorf(proto.CodeDialFailed, "%s resolves to %s, which is outside the network (no peer's allowed IPs contain it)", host, found[0])
	}
	return routed, nil
}

// Dial opens TCP to host:port through the tunnel.
func (n *Node) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	addrs, err := n.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, a := range addrs {
		c, err := n.tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(a, uint16(port)))
		if err == nil {
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// peerStats reads the device's per-peer counters.
type peerStat struct {
	rx, tx    uint64
	handshake int64 // ms, 0 = never
	endpoint  string
}

func (n *Node) stats() map[string]*peerStat {
	out := map[string]*peerStat{}
	text, err := n.dev.IpcGet()
	if err != nil {
		return out
	}
	var cur *peerStat
	var sec, nsec int64
	flush := func() {
		if cur != nil && sec > 0 {
			cur.handshake = time.Unix(sec, nsec).UnixMilli()
		}
		sec, nsec = 0, 0
	}
	for _, line := range strings.Split(text, "\n") {
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch k {
		case "public_key":
			flush()
			cur = &peerStat{}
			out[v] = cur
		case "rx_bytes":
			if cur != nil {
				cur.rx, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.tx, _ = strconv.ParseUint(v, 10, 64)
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "endpoint":
			if cur != nil {
				cur.endpoint = v
			}
		}
	}
	flush()
	return out
}

// Info is the node's state and counters.
func (n *Node) Info() netd.NodeInfo {
	info := netd.NodeInfo{State: proto.StateUp}
	addrs := make([]string, 0, len(n.plan.prefixes))
	for _, p := range n.plan.prefixes {
		addrs = append(addrs, p.String())
	}
	info.Node = &proto.Node{Addresses: addrs, PublicKey: n.plan.private.PublicKey().String()}
	for _, s := range n.stats() {
		info.RxBytes += s.rx
		info.TxBytes += s.tx
		if s.handshake > info.LastHandshakeAt {
			info.LastHandshakeAt = s.handshake
		}
	}
	return info
}

// Peers are the configured peers (WireGuard has no discovery), online when
// their last handshake is under 3 minutes old.
func (n *Node) Peers(context.Context) ([]proto.Peer, error) {
	stats := n.stats()
	now := time.Now().UnixMilli()
	out := make([]proto.Peer, 0, len(n.plan.peers))
	for _, pp := range n.plan.peers {
		pub := pp.public.String()
		name := pp.endpoint
		if name == "" {
			name = pub[:8] + "…"
		}
		addrs := make([]string, 0, len(pp.allowed))
		for _, a := range pp.allowed {
			if a.IsSingleIP() {
				addrs = append(addrs, a.Addr().String())
			} else {
				addrs = append(addrs, a.String())
			}
		}
		peer := proto.Peer{Name: name, Addresses: addrs, PublicKey: pub, Endpoint: pp.endpoint}
		if s := stats[pp.public.hex()]; s != nil {
			online := s.handshake > 0 && now-s.handshake < 3*60*1000
			peer.Online = &online
			peer.LastSeen = s.handshake
		}
		out = append(out, peer)
	}
	return out, nil
}

// GenerateKey makes a new private key.
func GenerateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}
