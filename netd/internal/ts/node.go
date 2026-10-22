//go:build tailscale

package ts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/wgengine/netstack"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/proto"
)

// logoutTimeout bounds the logout of a node that stops.
const logoutTimeout = 5 * time.Second

// Backend joins Tailscale tailnets and Headscale servers: one tsnet node
// per network.
type Backend struct {
	// StateDir is netd's state directory (--state-dir): persistent nodes
	// keep their state under it, ephemeral ones their scratch files.
	StateDir string
	// Verbose passes tsnet's backend logs to netd's debug log.
	Verbose bool

	mu      sync.Mutex
	live    map[string]*Node // by network id, until closed
	cleaned bool
}

func (b *Backend) dirs() stateDir {
	base := b.StateDir
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("termoak-netd-%d", os.Getuid()))
	}
	return newStateDir(base)
}

// prepare creates the state directory and, once, removes the leftovers
// of ephemeral nodes.
func (b *Backend) prepare(log *slog.Logger) (stateDir, error) {
	d := b.dirs()
	if err := d.ensure(); err != nil {
		return d, fmt.Errorf("could not create the state directory %s: %w", d.root, err)
	}
	b.mu.Lock()
	first := !b.cleaned
	b.cleaned = true
	b.mu.Unlock()
	if first {
		if n, err := d.cleanScratch(); err != nil {
			log.Warn("could not clean the scratch directories of ephemeral nodes", "error", err)
		} else if n > 0 {
			log.Info("removed leftovers of ephemeral nodes", "dirs", n)
		}
	}
	return d, nil
}

// waitPrevious waits until the previous node of a network (being replaced
// or taken down) has closed, so two nodes never share a state.
func (b *Backend) waitPrevious(ctx context.Context, id string) {
	b.mu.Lock()
	prev := b.live[id]
	b.mu.Unlock()
	if prev == nil {
		return
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	select {
	case <-prev.closed:
	case <-wait.Done():
	}
}

// Start creates the network's tsnet node and starts it in the background:
// it returns at once, the node reports starting / needs_auth / up / error
// (Settled waits for it).
func (b *Backend) Start(ctx context.Context, spec *proto.Spec, log *slog.Logger) (netd.Node, error) {
	p, err := parse(spec)
	if err != nil {
		return nil, err
	}
	d, err := b.prepare(log)
	if err != nil {
		return nil, err
	}
	b.waitPrevious(ctx, spec.ID)

	persistent := d.persistent(spec.ID)
	var dir string
	var store ipn.StateStore
	if p.ephemeral {
		if hasState(persistent) {
			// The network was persistent: its old node leaves first.
			log.Info("the network became ephemeral: logging its persistent node out")
			if err := b.forgetDir(ctx, persistent, log); err != nil {
				log.Warn("could not log the persistent node out", "error", err)
			}
		}
		if dir, err = d.scratch(spec.ID); err != nil {
			return nil, fmt.Errorf("could not create the node's directory: %w", err)
		}
		store = new(mem.Store)
	} else {
		dir = persistent
		if hasState(dir) {
			if m, err := readMarker(dir); err != nil || m.ControlURL != p.controlURL {
				log.Info("the control server changed: logging the old node out")
				if err := b.forgetDir(ctx, dir, log); err != nil {
					log.Warn("could not log the old node out", "error", err)
				}
			}
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("could not create the node's state directory: %w", err)
		}
		if err := writeMarker(dir, marker{ControlURL: p.controlURL}); err != nil {
			return nil, fmt.Errorf("could not write the node's state: %w", err)
		}
		// nil: tsnet keeps it in dir/tailscaled.state (0600).
	}

	s := &tsnet.Server{
		Dir:           dir,
		Store:         store,
		Hostname:      p.hostname,
		Ephemeral:     p.ephemeral,
		AuthKey:       p.authKey,
		ControlURL:    p.controlURL,
		AdvertiseTags: p.tags,
		UserLogf: func(format string, args ...any) {
			log.Debug("tsnet: " + fmt.Sprintf(format, args...))
		},
	}
	if b.Verbose {
		s.Logf = func(format string, args ...any) {
			log.Debug("tailscale: " + fmt.Sprintf(format, args...))
		}
	}
	cleanup := func() {
		if p.ephemeral {
			_ = os.RemoveAll(dir)
		}
	}
	if err := s.Start(); err != nil {
		cleanup()
		return nil, fmt.Errorf("could not start the Tailscale node: %s", strings.TrimPrefix(err.Error(), "tsnet: "))
	}
	lc, err := s.LocalClient()
	if err != nil {
		_ = s.Close()
		cleanup()
		return nil, fmt.Errorf("could not start the Tailscale node: %w", err)
	}
	ns, ok := s.Sys().Netstack.Get().(*netstack.Impl)
	if !ok {
		_ = s.Close()
		cleanup()
		return nil, errors.New("the Tailscale node has no user-space network stack")
	}
	nctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		b: b, id: spec.ID, p: p, s: s, lc: lc, ns: ns, log: log, dir: dir,
		ctx: nctx, cancel: cancel,
		backend: bsNoState, changed: make(chan struct{}), closed: make(chan struct{}),
	}
	b.mu.Lock()
	if b.live == nil {
		b.live = map[string]*Node{}
	}
	b.live[spec.ID] = n
	b.mu.Unlock()
	go n.watch()
	log.Info("tailscale node starting", "hostname", p.hostname, "control_url", p.effectiveControlURL(),
		"tags", p.tags, "ephemeral", p.ephemeral, "auth_key", p.authKey != "")
	return n, nil
}

// forgetDir logs a persistent node out of its control server (starting it
// from its state) and removes its directory.
func (b *Backend) forgetDir(ctx context.Context, dir string, log *slog.Logger) error {
	defer os.RemoveAll(dir)
	if !hasState(dir) {
		return nil
	}
	m, err := readMarker(dir)
	if err != nil {
		return err
	}
	s := &tsnet.Server{
		Dir:        dir,
		Hostname:   "termoak-leaving",
		ControlURL: m.ControlURL,
		UserLogf:   func(string, ...any) {},
	}
	if err := s.Start(); err != nil {
		return err
	}
	defer s.Close()
	lc, err := s.LocalClient()
	if err != nil {
		return err
	}
	lctx, cancel := context.WithTimeout(ctx, 3*logoutTimeout)
	defer cancel()
	if err := lc.Logout(lctx); err != nil {
		return err
	}
	log.Info("persistent tailscale node logged out")
	return nil
}

// Forget removes what netd keeps of a network that is not running: a
// persistent node is logged out and its state deleted.
func (b *Backend) Forget(ctx context.Context, id string, log *slog.Logger) error {
	if !proto.ValidID(id) {
		return nil
	}
	d := b.dirs()
	dir := d.persistent(id)
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	b.waitPrevious(ctx, id)
	return b.forgetDir(ctx, dir, log)
}

// Node is a running tsnet node.
type Node struct {
	b   *Backend
	id  string
	p   *plan
	s   *tsnet.Server
	lc  *local.Client
	ns  *netstack.Impl
	log *slog.Logger
	dir string

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	backend  string // ipn.State name
	authURL  string
	lastErr  string
	loggedIn bool          // it had a node key at some point (logout on close)
	changed  chan struct{} // closed and replaced on every change

	closeOnce sync.Once
	closed    chan struct{}
}

// watch follows the node's state on its IPN bus.
func (n *Node) watch() {
	for n.ctx.Err() == nil {
		w, err := n.lc.WatchIPNBus(n.ctx, ipn.NotifyInitialState)
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		for {
			nt, err := w.Next()
			if err != nil {
				break
			}
			n.apply(&nt)
		}
		w.Close()
	}
}

func (n *Node) apply(nt *ipn.Notify) {
	n.mu.Lock()
	defer n.mu.Unlock()
	changed := false
	if nt.State != nil {
		st := nt.State.String()
		if st != n.backend {
			n.log.Info("tailscale state", "from", n.backend, "to", st)
		}
		n.backend = st
		switch *nt.State {
		case ipn.Running:
			n.lastErr, n.authURL = "", ""
			n.loggedIn = true
		case ipn.NeedsMachineAuth:
			n.loggedIn = true
		}
		changed = true
	}
	if nt.BrowseToURL != nil && *nt.BrowseToURL != "" {
		n.authURL = *nt.BrowseToURL
		n.log.Info("tailscale node needs a login")
		changed = true
	}
	if nt.ErrMessage != nil && *nt.ErrMessage != "" {
		// tsnet retries with a backoff: log each error once.
		if *nt.ErrMessage != n.lastErr {
			n.log.Warn("tailscale error", "error", *nt.ErrMessage)
		}
		n.lastErr = *nt.ErrMessage
		changed = true
	}
	if nt.LoginFinished != nil {
		n.lastErr = ""
		changed = true
	}
	if changed {
		close(n.changed)
		n.changed = make(chan struct{})
	}
}

func (n *Node) view() (view, chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return view{backend: n.backend, authURL: n.authURL, lastErr: n.lastErr, hasKey: n.p.authKey != ""}, n.changed
}

// Settled waits until the node is up, waits for authorization or failed.
func (n *Node) Settled(ctx context.Context) {
	for {
		v, ch := n.view()
		if mapState(v).state != proto.StateStarting {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return
		case <-n.closed:
			return
		}
	}
}

func (n *Node) status(timeout time.Duration) (*ipnstate.Status, error) {
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	return n.lc.Status(ctx)
}

// Info is the node's state, addresses and tailnet.
func (n *Node) Info() netd.NodeInfo {
	v, _ := n.view()
	st, err := n.status(2 * time.Second)
	if err == nil && v.authURL == "" && st.AuthURL != "" && st.BackendState == bsNeedsLogin {
		v.authURL = st.AuthURL
	}
	m := mapState(v)
	eph := n.p.ephemeral
	info := netd.NodeInfo{
		State: m.state, Message: m.message, Auth: m.auth,
		ControlURL: n.p.effectiveControlURL(), Ephemeral: &eph, LastError: v.lastErr,
	}
	node := &proto.Node{Name: n.p.hostname, Addresses: []string{}}
	if m.auth == proto.AuthLogin {
		node.AuthURL = v.authURL
	}
	if err == nil && st != nil {
		for _, a := range st.TailscaleIPs {
			node.Addresses = append(node.Addresses, a.String())
		}
		if st.Self != nil {
			node.NodeID = string(st.Self.ID)
			node.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
			if h := hostOf(node.DNSName); h != "" {
				node.Name = h
			}
		}
		if st.CurrentTailnet != nil {
			info.Tailnet = st.CurrentTailnet.Name
			info.MagicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
		} else if st.MagicDNSSuffix != "" {
			info.MagicDNSSuffix = st.MagicDNSSuffix
		}
		if m.state == proto.StateUp {
			count := len(st.Peer)
			info.PeerCount = &count
			for _, ps := range st.Peer {
				info.RxBytes += uint64(max(ps.RxBytes, 0))
				info.TxBytes += uint64(max(ps.TxBytes, 0))
				if h := ps.LastHandshake.UnixMilli(); !ps.LastHandshake.IsZero() && h > info.LastHandshakeAt {
					info.LastHandshakeAt = h
				}
			}
		}
	}
	info.Node = node
	return info
}

// hostOf is the first label of a DNS name.
func hostOf(dns string) string {
	h, _, _ := strings.Cut(dns, ".")
	return h
}

// Peers are the devices of the tailnet this node sees.
func (n *Node) Peers(ctx context.Context) ([]proto.Peer, error) {
	st, err := n.lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return peersOf(st), nil
}

func peersOf(st *ipnstate.Status) []proto.Peer {
	out := make([]proto.Peer, 0, len(st.Peer))
	for _, ps := range st.Peer {
		p := proto.Peer{
			Name:      ps.HostName,
			DNSName:   strings.TrimSuffix(ps.DNSName, "."),
			Addresses: make([]string, 0, len(ps.TailscaleIPs)),
			OS:        ps.OS,
			ID:        string(ps.ID),
		}
		if p.Name == "" {
			p.Name = hostOf(p.DNSName)
		}
		for _, a := range ps.TailscaleIPs {
			p.Addresses = append(p.Addresses, a.String())
		}
		online := ps.Online
		p.Online = &online
		if !ps.LastSeen.IsZero() {
			p.LastSeen = ps.LastSeen.UnixMilli()
		} else if online {
			p.LastSeen = time.Now().UnixMilli()
		}
		if ps.Tags != nil {
			p.Tags = ps.Tags.AsSlice()
		}
		if ps.PrimaryRoutes != nil {
			for _, r := range ps.PrimaryRoutes.All() {
				if r.Bits() > 0 {
					p.Routes = append(p.Routes, r.String())
				}
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DNSName != out[j].DNSName {
			return out[i].DNSName < out[j].DNSName
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// tailnetOf is what a dial may reach: the peers' addresses and the
// subnets they route (never an exit node's default route), and the
// MagicDNS names.
func tailnetOf(st *ipnstate.Status) *tailnet {
	t := &tailnet{names: map[string][]netip.Addr{}}
	if st.CurrentTailnet != nil {
		t.suffix = strings.ToLower(strings.Trim(st.CurrentTailnet.MagicDNSSuffix, "."))
	} else {
		t.suffix = strings.ToLower(strings.Trim(st.MagicDNSSuffix, "."))
	}
	for _, ps := range st.Peer {
		if ps.AllowedIPs != nil {
			for _, r := range ps.AllowedIPs.All() {
				if r.Bits() > 0 {
					t.routes = append(t.routes, r)
				}
			}
		}
		for _, a := range ps.TailscaleIPs {
			t.routes = append(t.routes, netip.PrefixFrom(a, a.BitLen()))
		}
		dns := strings.ToLower(strings.TrimSuffix(ps.DNSName, "."))
		if dns != "" {
			t.names[dns] = append(t.names[dns], ps.TailscaleIPs...)
		}
	}
	for _, r := range st.ExtraRecords {
		if a, err := netip.ParseAddr(r.Value); err == nil {
			name := strings.ToLower(strings.TrimSuffix(r.Name, "."))
			t.names[name] = append(t.names[name], a)
		}
	}
	return t
}

// Dial opens TCP to host:port inside the tailnet, always through the
// node's own netstack: never the host's kernel network stack (tsnet's
// Dial would use it for an address outside the tailnet), never through an
// exit node.
func (n *Node) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	st, err := n.lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	t := tailnetOf(st)
	addrs, err := t.resolve(ctx, host, net.DefaultResolver.LookupNetIP)
	if err != nil {
		return nil, err
	}
	v4, v6 := n.s.TailscaleIPs()
	var lastErr error
	for _, a := range addrs {
		src := v4
		if a.Is6() {
			src = v6
		}
		if !src.IsValid() {
			lastErr = fmt.Errorf("the node has no IPv%d address", map[bool]int{true: 6, false: 4}[a.Is6()])
			continue
		}
		c, err := n.ns.DialContextTCPWithBind(ctx, src, netip.AddrPortFrom(a, uint16(port)))
		if err == nil {
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no address to dial")
	}
	return nil, lastErr
}

// Close takes the node down. An ephemeral node logs out first, so the
// control server deletes it at once (else it lingers until its inactivity
// timeout); a persistent one stays registered (offline) for next time.
func (n *Node) Close() error {
	n.close(n.p.ephemeral)
	return nil
}

// CloseAndForget logs the node out and removes its state (the network was
// deleted).
func (n *Node) CloseAndForget() error {
	n.close(true)
	return os.RemoveAll(n.dir)
}

func (n *Node) close(logout bool) {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		loggedIn := n.loggedIn
		n.mu.Unlock()
		if logout && loggedIn {
			ctx, cancel := context.WithTimeout(context.Background(), logoutTimeout)
			if err := n.lc.Logout(ctx); err != nil {
				n.log.Warn("could not log the tailscale node out", "error", err)
			} else {
				n.log.Info("tailscale node logged out")
			}
			cancel()
		}
		n.cancel()
		_ = n.s.Close()
		if n.p.ephemeral {
			_ = os.RemoveAll(n.dir)
		}
		n.b.mu.Lock()
		if n.b.live[n.id] == n {
			delete(n.b.live, n.id)
		}
		n.b.mu.Unlock()
		close(n.closed)
	})
}
