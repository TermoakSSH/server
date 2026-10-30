package netd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TermoakSSH/server/netd/internal/proto"
)

// Limits of a Manager.
type Limits struct {
	// MaxNetworks up at the same time. When full, the least recently used
	// network without open connections is taken down for a new one;
	// otherwise `limit`.
	MaxNetworks int
	// KindMax caps the networks of one kind up at the same time (same
	// rule), e.g. Tailscale nodes, which take far more memory than
	// WireGuard ones. 0 or missing: only MaxNetworks.
	KindMax map[string]int
	// MaxStreams open at the same time per network.
	MaxStreams int
	// Idle: a network without connections for this long is taken down
	// (0: never).
	Idle time.Duration
	// MaxDialTimeout caps timeout_ms; DefaultDialTimeout is used without it.
	MaxDialTimeout     time.Duration
	DefaultDialTimeout time.Duration
	// StartTimeout: how long `up` waits for a node before answering
	// `starting`.
	StartTimeout time.Duration
}

// DefaultMaxTailscale: Tailscale nodes up at the same time by default. A
// tsnet node takes 2–3 MiB in a small tailnet and more with many peers
// (docs/NETWORKS.md §6.6): 16 of them stay well inside the 512 MiB of the
// systemd unit, with room for the WireGuard networks and the connections.
const DefaultMaxTailscale = 16

// DefaultLimits are the defaults of the command line.
func DefaultLimits() Limits {
	return Limits{
		MaxNetworks:        64,
		KindMax:            map[string]int{"tailscale": DefaultMaxTailscale},
		MaxStreams:         256,
		Idle:               15 * time.Minute,
		MaxDialTimeout:     2 * time.Minute,
		DefaultDialTimeout: 20 * time.Second,
		StartTimeout:       10 * time.Second,
	}
}

// Manager keeps the running networks, one isolated node per network id.
type Manager struct {
	limits Limits
	log    *slog.Logger
	now    func() time.Time

	mu    sync.Mutex
	nodes map[string]*entry
}

// entry is one network (starting, up or failed).
type entry struct {
	id, name, kind, revision, vault string
	log                             *slog.Logger

	ready chan struct{} // closed when the start finished
	// Set before ready is closed.
	node     Node
	startErr error
	forget   atomic.Bool // closeEntry removes what the backend keeps

	created  time.Time
	since    time.Time    // set before ready is closed
	lastUsed atomic.Int64 // ms
	streams  atomic.Int32
	dials    atomic.Uint64
	failed   atomic.Uint64
	closed   atomic.Bool
}

// NewManager makes a manager.
func NewManager(limits Limits, log *slog.Logger) *Manager {
	return &Manager{limits: limits, log: log, now: time.Now, nodes: map[string]*entry{}}
}

func ms(t time.Time) int64 { return t.UnixMilli() }

// Up brings spec's network up (or restarts it if its revision changed) and
// waits up to the start timeout.
func (m *Manager) Up(ctx context.Context, spec *proto.Spec) (proto.Status, error) {
	e, err := m.ensure(spec)
	if err != nil {
		return proto.Status{}, err
	}
	wait, cancel := context.WithTimeout(ctx, m.limits.StartTimeout)
	defer cancel()
	select {
	case <-e.ready:
		// A node that joins in the background (Tailscale) answers once it
		// is up, waits for authorization or failed (or `starting`).
		if s, ok := e.node.(Settler); ok && e.startErr == nil {
			s.Settled(wait)
		}
	case <-wait.Done():
	}
	// An `up` is a use: the idle time counts from its answer (a node that
	// took a while to join is not taken down right away).
	e.lastUsed.Store(ms(m.now()))
	return m.status(e), nil
}

// ensure returns the entry of spec, starting it if needed.
func (m *Manager) ensure(spec *proto.Spec) (*entry, error) {
	if err := spec.Validate(); err != nil {
		return nil, proto.Errorf(proto.CodeInvalid, "%s", err)
	}
	backend, ok := backendFor(spec.Kind)
	if !ok {
		if msg, planned := plannedKinds[spec.Kind]; planned {
			return nil, proto.Errorf(proto.CodeUnsupportedKind, "%s", msg)
		}
		return nil, proto.Errorf(proto.CodeUnsupportedKind, "unknown network kind %q", spec.Kind)
	}
	m.mu.Lock()
	var old []*entry
	e := m.nodes[spec.ID]
	if e != nil {
		failed := false
		select {
		case <-e.ready:
			failed = e.startErr != nil
		default:
		}
		if e.revision == spec.Revision && e.kind == spec.Kind && !failed {
			m.mu.Unlock()
			return e, nil
		}
		// Another revision (or a failed start): replace it.
		delete(m.nodes, spec.ID)
		old = append(old, e)
		reason := "revision changed"
		if failed {
			reason = "retrying after an error"
		}
		e.log.Info("restarting network", "reason", reason, "new_revision", spec.Revision)
	}
	if max := m.limits.KindMax[spec.Kind]; max > 0 && m.countKind(spec.Kind) >= max {
		victim := m.lruIdle(spec.Kind)
		if victim == nil {
			m.mu.Unlock()
			m.closeAll(old, "replaced")
			return nil, proto.Errorf(proto.CodeLimit, "termoak-netd already runs %d %s networks with open connections (its limit for that kind)", max, kindName(spec.Kind))
		}
		delete(m.nodes, victim.id)
		old = append(old, victim)
		victim.log.Info("taking network down to make room", "kind_max", max)
	}
	if m.limits.MaxNetworks > 0 && len(m.nodes) >= m.limits.MaxNetworks {
		victim := m.lruIdle("")
		if victim == nil {
			m.mu.Unlock()
			m.closeAll(old, "replaced")
			return nil, proto.Errorf(proto.CodeLimit, "termoak-netd already runs %d networks with open connections", len(m.nodes))
		}
		delete(m.nodes, victim.id)
		old = append(old, victim)
		victim.log.Info("taking network down to make room", "max_networks", m.limits.MaxNetworks)
	}
	now := m.now()
	e = &entry{
		id: spec.ID, name: spec.Name, kind: spec.Kind, revision: spec.Revision, vault: spec.VaultID,
		ready:   make(chan struct{}),
		created: now,
	}
	e.log = m.log.With("network", spec.ID, "kind", spec.Kind)
	if spec.VaultID != "" {
		e.log = e.log.With("vault", spec.VaultID)
	}
	e.lastUsed.Store(ms(now))
	m.nodes[spec.ID] = e
	m.mu.Unlock()
	m.closeAll(old, "replaced")

	e.log.Info("starting network", "revision", spec.Revision)
	// The spec (and its secret) is only used by the backend's Start.
	go func(spec proto.Spec) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		started := time.Now()
		node, err := backend.Start(ctx, &spec, e.log)
		e.node, e.startErr = node, err
		e.since = m.now()
		close(e.ready)
		if err != nil {
			e.log.Warn("network could not start", "error", err)
			return
		}
		if e.closed.Load() {
			// Taken down while starting.
			_ = node.Close()
			return
		}
		e.log.Info("network up", "took_ms", time.Since(started).Milliseconds())
	}(*spec)
	return e, nil
}

// kindName is how errors name a kind.
func kindName(kind string) string {
	switch kind {
	case "wireguard":
		return "WireGuard"
	case "tailscale":
		return "Tailscale"
	case "zerotier":
		return "ZeroTier"
	}
	return kind
}

// countKind is how many networks of a kind run (mu held).
func (m *Manager) countKind(kind string) int {
	n := 0
	for _, e := range m.nodes {
		if e.kind == kind {
			n++
		}
	}
	return n
}

// lruIdle is the least recently used network without connections, of kind
// (any kind when empty) (mu held).
func (m *Manager) lruIdle(kind string) *entry {
	var best *entry
	for _, e := range m.nodes {
		if e.streams.Load() > 0 || (kind != "" && e.kind != kind) {
			continue
		}
		if best == nil || e.lastUsed.Load() < best.lastUsed.Load() {
			best = e
		}
	}
	return best
}

func (m *Manager) closeAll(list []*entry, reason string) {
	for _, e := range list {
		m.closeEntry(e, reason)
	}
}

// closeEntry stops a node that is no longer in the map.
func (m *Manager) closeEntry(e *entry, reason string) {
	if e.closed.Swap(true) {
		return
	}
	go func() {
		<-e.ready
		closeNode(e)
		e.log.Info("network down", "reason", reason, "dials", e.dials.Load(), "dials_failed", e.failed.Load())
	}()
}

// closeNode closes a started node (forgetting it when asked).
func closeNode(e *entry) {
	if e.node == nil {
		return
	}
	if fc, ok := e.node.(ForgetCloser); ok && e.forget.Load() {
		if err := fc.CloseAndForget(); err != nil {
			e.log.Warn("could not forget the network's node", "error", err)
		}
		return
	}
	_ = e.node.Close()
}

// Down takes a network down (nothing happens if it was not up).
func (m *Manager) Down(id string, reason string) bool {
	return m.down(id, reason, false)
}

// Forget takes a network down and removes what the backends keep of it
// (the network was deleted): a running node is closed that way, and every
// backend that keeps state between runs forgets the id (in the
// background).
func (m *Manager) Forget(id string) bool {
	was := m.down(id, "deleted", true)
	if !was {
		for _, f := range forgetters() {
			go func(f Forgetter) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				log := m.log.With("network", id)
				if err := f.Forget(ctx, id, log); err != nil {
					log.Warn("could not forget the network", "error", err)
				}
			}(f)
		}
	}
	return was
}

func (m *Manager) down(id, reason string, forget bool) bool {
	m.mu.Lock()
	e := m.nodes[id]
	delete(m.nodes, id)
	m.mu.Unlock()
	if e == nil {
		return false
	}
	if forget {
		e.forget.Store(true)
	}
	m.closeEntry(e, reason)
	return true
}

// DownAll takes every network down (shutdown).
func (m *Manager) DownAll(reason string) {
	m.mu.Lock()
	list := make([]*entry, 0, len(m.nodes))
	for id, e := range m.nodes {
		list = append(list, e)
		delete(m.nodes, id)
	}
	m.mu.Unlock()
	// In parallel: a Tailscale node logs out of its control server.
	var wg sync.WaitGroup
	for _, e := range list {
		if e.closed.Swap(true) {
			continue
		}
		wg.Add(1)
		go func(e *entry) {
			defer wg.Done()
			select {
			case <-e.ready:
			case <-time.After(5 * time.Second):
				return
			}
			closeNode(e)
			e.log.Info("network down", "reason", reason)
		}(e)
	}
	wg.Wait()
}

// Status of a network, without bringing it up.
func (m *Manager) Status(id string) proto.Status {
	m.mu.Lock()
	e := m.nodes[id]
	m.mu.Unlock()
	if e == nil {
		return proto.Status{NetworkID: id, State: proto.StateDown}
	}
	st := m.status(e)
	if st.State == proto.StateStarting {
		// Someone is waiting for it (an app polls while a Tailscale node
		// joins, after `up` answered "starting"): that is a use, or a
		// short idle time would take the node down before it is up.
		e.lastUsed.Store(ms(m.now()))
	}
	return st
}

// List is the status of every network netd runs.
func (m *Manager) List() []proto.Status {
	m.mu.Lock()
	list := make([]*entry, 0, len(m.nodes))
	for _, e := range m.nodes {
		list = append(list, e)
	}
	m.mu.Unlock()
	out := make([]proto.Status, 0, len(list))
	for _, e := range list {
		out = append(out, m.status(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NetworkID < out[j].NetworkID })
	return out
}

func (m *Manager) status(e *entry) proto.Status {
	st := proto.Status{
		NetworkID:   e.id,
		Revision:    e.revision,
		LastUsedAt:  e.lastUsed.Load(),
		Streams:     int(e.streams.Load()),
		Dials:       e.dials.Load(),
		DialsFailed: e.failed.Load(),
	}
	select {
	case <-e.ready:
	default:
		st.State = proto.StateStarting
		st.Since = ms(e.created)
		return st
	}
	st.Since = ms(e.since)
	if e.startErr != nil {
		st.State = proto.StateError
		st.Message = e.startErr.Error()
		return st
	}
	info := e.node.Info()
	st.State = info.State
	if st.State == "" {
		st.State = proto.StateUp
	}
	st.Message = info.Message
	st.Node = info.Node
	st.RxBytes, st.TxBytes = info.RxBytes, info.TxBytes
	st.LastHandshakeAt = info.LastHandshakeAt
	st.Auth, st.ControlURL, st.LastError = info.Auth, info.ControlURL, info.LastError
	st.Tailnet, st.MagicDNSSuffix = info.Tailnet, info.MagicDNSSuffix
	st.PeerCount, st.Ephemeral = info.PeerCount, info.Ephemeral
	return st
}

// Peers brings the network up if needed and lists its devices.
func (m *Manager) Peers(ctx context.Context, spec *proto.Spec) ([]proto.Peer, error) {
	e, err := m.ensure(spec)
	if err != nil {
		return nil, err
	}
	node, err := m.waitNode(ctx, e)
	if err != nil {
		return nil, err
	}
	e.lastUsed.Store(ms(m.now()))
	peers, err := node.Peers(ctx)
	if err != nil {
		return nil, proto.Errorf(proto.CodeNetworkError, "%s", err)
	}
	return peers, nil
}

// waitNode waits for a started node.
func (m *Manager) waitNode(ctx context.Context, e *entry) (Node, error) {
	select {
	case <-e.ready:
	case <-ctx.Done():
		return nil, proto.Errorf(proto.CodeTimeout, "the network %q did not start in time", e.name)
	}
	if e.startErr != nil {
		var pe *proto.Error
		if errors.As(e.startErr, &pe) {
			return nil, pe
		}
		return nil, proto.Errorf(proto.CodeNetworkError, "the network %q could not start: %s", e.name, e.startErr)
	}
	if s, ok := e.node.(Settler); ok {
		s.Settled(ctx)
	}
	info := e.node.Info()
	switch info.State {
	case proto.StateNeedsAuth:
		pe := proto.Errorf(proto.CodeNeedsAuth, "the network %q waits for authorization: %s", e.name, info.Message)
		pe.Auth = info.Auth
		return nil, pe
	case proto.StateError:
		return nil, proto.Errorf(proto.CodeNetworkError, "the network %q could not start: %s", e.name, info.Message)
	case proto.StateStarting:
		return nil, proto.Errorf(proto.CodeTimeout, "the network %q is still starting: %s", e.name, info.Message)
	}
	return e.node, nil
}

// DialTimeout is the timeout of a dial request (timeout_ms, capped).
func (m *Manager) DialTimeout(timeoutMs int64) time.Duration {
	d := m.limits.DefaultDialTimeout
	if timeoutMs > 0 {
		d = time.Duration(timeoutMs) * time.Millisecond
	}
	if m.limits.MaxDialTimeout > 0 && d > m.limits.MaxDialTimeout {
		d = m.limits.MaxDialTimeout
	}
	return d
}

// Stream is an open connection inside a network; Done must be called once
// when it ends.
type Stream struct {
	net.Conn
	e    *entry
	m    *Manager
	once sync.Once
}

// Done releases the stream's slot.
func (s *Stream) Done() {
	s.once.Do(func() {
		s.e.streams.Add(-1)
		s.e.lastUsed.Store(ms(s.m.now()))
	})
}

// Log is the network's logger.
func (s *Stream) Log() *slog.Logger { return s.e.log }

// Dial opens host:port inside spec's network (brought up if needed).
func (m *Manager) Dial(ctx context.Context, spec *proto.Spec, host string, port int) (*Stream, error) {
	if host == "" || len(host) > 253 {
		return nil, proto.Errorf(proto.CodeInvalid, "invalid host")
	}
	if port < 1 || port > 65535 {
		return nil, proto.Errorf(proto.CodeInvalid, "invalid port")
	}
	e, err := m.ensure(spec)
	if err != nil {
		return nil, err
	}
	if n := e.streams.Add(1); m.limits.MaxStreams > 0 && int(n) > m.limits.MaxStreams {
		e.streams.Add(-1)
		return nil, proto.Errorf(proto.CodeLimit, "the network %q already has %d open connections", e.name, m.limits.MaxStreams)
	}
	e.lastUsed.Store(ms(m.now()))
	release := func() {
		e.streams.Add(-1)
		e.lastUsed.Store(ms(m.now()))
	}
	node, err := m.waitNode(ctx, e)
	if err != nil {
		release()
		e.failed.Add(1)
		return nil, err
	}
	e.dials.Add(1)
	conn, err := node.Dial(ctx, host, port)
	if err != nil {
		release()
		e.failed.Add(1)
		var pe *proto.Error
		if !errors.As(err, &pe) {
			pe = classifyDialError(ctx, err, host, port, e)
		}
		e.log.Info("dial failed", "host", host, "port", port, "code", pe.Code, "error", pe.Message)
		return nil, pe
	}
	return &Stream{Conn: conn, e: e, m: m}, nil
}

func classifyDialError(ctx context.Context, err error, host string, port int, e *entry) *proto.Error {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		msg := "no answer from %s:%d inside the network %q in time"
		if e.node != nil && e.node.Info().LastHandshakeAt == 0 && e.kind == "wireguard" {
			msg += " (no WireGuard handshake with the peer yet: check its endpoint and that it has the server's public key)"
		}
		return proto.Errorf(proto.CodeTimeout, msg, host, port, e.name)
	}
	return proto.Errorf(proto.CodeDialFailed, "could not connect to %s:%d inside the network %q: %s", host, port, e.name, err)
}

// Reap takes down networks idle for longer than the limit; returns how
// many.
func (m *Manager) Reap() int {
	if m.limits.Idle <= 0 {
		return 0
	}
	cutoff := ms(m.now().Add(-m.limits.Idle))
	m.mu.Lock()
	var idle []*entry
	for id, e := range m.nodes {
		if e.streams.Load() == 0 && e.lastUsed.Load() <= cutoff {
			idle = append(idle, e)
			delete(m.nodes, id)
		}
	}
	m.mu.Unlock()
	for _, e := range idle {
		m.closeEntry(e, "idle")
	}
	return len(idle)
}

// RunReaper calls Reap every tick until ctx ends.
func (m *Manager) RunReaper(ctx context.Context, tick time.Duration) {
	if m.limits.Idle <= 0 {
		return
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Reap()
		}
	}
}

// Count is how many networks netd runs.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.nodes)
}
