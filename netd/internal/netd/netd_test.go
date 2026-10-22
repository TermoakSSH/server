package netd_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/proto"
	"github.com/TermoakSSH/server/netd/internal/wg"
	"github.com/TermoakSSH/server/netd/internal/wgtest"
)

func init() {
	netd.Register("wireguard", &wg.Backend{})
	netd.Register("fake", fakeBackend{})
}

func testLog() *slog.Logger {
	if os.Getenv("NETD_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- A fake backend (manager behavior without WireGuard) ---------------------

type fakeBackend struct{}

type fakeNode struct {
	mu     sync.Mutex
	closed bool
	conns  []net.Conn
}

func (fakeBackend) Start(_ context.Context, spec *proto.Spec, _ *slog.Logger) (netd.Node, error) {
	if strings.Contains(string(spec.Config), "fail") {
		return nil, fmt.Errorf("bad config")
	}
	return &fakeNode{}, nil
}

func (n *fakeNode) Dial(_ context.Context, host string, port int) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, fmt.Errorf("closed")
	}
	a, b := net.Pipe()
	n.conns = append(n.conns, b)
	if host == "blackhole" {
		// A peer that vanished: reads everything, never answers or closes,
		// and our FIN goes nowhere.
		go func() { _, _ = io.Copy(io.Discard, b) }()
		return lostFIN{a}, nil
	} else {
		go func() { _, _ = io.Copy(b, b) }()
	}
	return a, nil
}

// lostFIN half-closes into the void.
type lostFIN struct{ net.Conn }

func (lostFIN) CloseWrite() error { return nil }

func (n *fakeNode) Info() netd.NodeInfo { return netd.NodeInfo{State: proto.StateUp} }
func (n *fakeNode) Peers(context.Context) ([]proto.Peer, error) {
	return []proto.Peer{{Name: "p", Addresses: []string{"10.0.0.1"}}}, nil
}
func (n *fakeNode) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	for _, c := range n.conns {
		_ = c.Close()
	}
	return nil
}

func fake(id, rev string) *proto.Spec {
	return &proto.Spec{ID: id, Name: id, Kind: "fake", Revision: rev, Config: json.RawMessage(`{}`), Secret: json.RawMessage(`{}`)}
}

func manager(l netd.Limits) *netd.Manager {
	if l.StartTimeout == 0 {
		l.StartTimeout = 5 * time.Second
	}
	if l.DefaultDialTimeout == 0 {
		l.DefaultDialTimeout = 5 * time.Second
	}
	return netd.NewManager(l, testLog())
}

func TestUpStatusDownAndRevisions(t *testing.T) {
	m := manager(netd.Limits{})
	if st := m.Status("a"); st.State != proto.StateDown {
		t.Fatalf("%+v", st)
	}
	st, err := m.Up(context.Background(), fake("a", "r1"))
	if err != nil || st.State != proto.StateUp || st.Revision != "r1" || st.Since == 0 {
		t.Fatalf("%+v %v", st, err)
	}
	s, err := m.Dial(context.Background(), fake("a", "r1"), "h", 22)
	if err != nil {
		t.Fatal(err)
	}
	if st := m.Status("a"); st.Streams != 1 || st.Dials != 1 {
		t.Fatalf("%+v", st)
	}
	// Another revision restarts the node: its connections end.
	if _, err := m.Up(context.Background(), fake("a", "r2")); err != nil {
		t.Fatal(err)
	}
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("the old connection is still open")
	}
	s.Done()
	if st := m.Status("a"); st.Revision != "r2" || st.State != proto.StateUp {
		t.Fatalf("%+v", st)
	}
	if !m.Down("a", "test") || m.Down("a", "test") {
		t.Fatal("down")
	}
	if st := m.Status("a"); st.State != proto.StateDown {
		t.Fatalf("%+v", st)
	}
	// A failed start is an error state, retried by the next request.
	bad := fake("b", "r1")
	bad.Config = json.RawMessage(`{"fail":true}`)
	if st, _ := m.Up(context.Background(), bad); st.State != proto.StateError || st.Message == "" {
		t.Fatalf("%+v", st)
	}
	_, err = m.Dial(context.Background(), bad, "h", 22)
	if pe := asProto(t, err); pe.Code != proto.CodeNetworkError {
		t.Fatalf("%+v", pe)
	}
	if _, err := m.Up(context.Background(), fake("b", "r1")); err != nil {
		t.Fatal(err)
	}
	if st := m.Status("b"); st.State != proto.StateUp {
		t.Fatalf("%+v", st)
	}
}

func asProto(t *testing.T, err error) *proto.Error {
	t.Helper()
	pe, ok := err.(*proto.Error)
	if !ok {
		t.Fatalf("not a protocol error: %v", err)
	}
	return pe
}

func TestKindsAndValidation(t *testing.T) {
	m := manager(netd.Limits{})
	for _, kind := range []string{"tailscale", "zerotier", "carrier-pigeon"} {
		s := fake("k", "r")
		s.Kind = kind
		_, err := m.Up(context.Background(), s)
		if pe := asProto(t, err); pe.Code != proto.CodeUnsupportedKind {
			t.Fatalf("%s: %+v", kind, pe)
		}
	}
	for _, s := range []*proto.Spec{nil, {ID: "", Kind: "fake"}, {ID: "x/y", Kind: "fake"}, {ID: "a"}} {
		_, err := m.Up(context.Background(), s)
		if pe := asProto(t, err); pe.Code != proto.CodeInvalid {
			t.Fatalf("%+v", pe)
		}
	}
	for _, hp := range []struct {
		h string
		p int
	}{{"", 22}, {"h", 0}, {"h", 70000}} {
		_, err := m.Dial(context.Background(), fake("a", "r"), hp.h, hp.p)
		if pe := asProto(t, err); pe.Code != proto.CodeInvalid {
			t.Fatalf("%+v", pe)
		}
	}
	kinds := netd.Kinds()
	if strings.Join(kinds, ",") != "fake,slow,wireguard" {
		t.Fatalf("%v", kinds)
	}
}

func TestLimits(t *testing.T) {
	m := manager(netd.Limits{MaxNetworks: 2, MaxStreams: 1})
	s1, err := m.Dial(context.Background(), fake("a", "r"), "h", 22)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Dial(context.Background(), fake("a", "r"), "h", 22)
	if pe := asProto(t, err); pe.Code != proto.CodeLimit {
		t.Fatalf("%+v", pe)
	}
	s2, err := m.Dial(context.Background(), fake("b", "r"), "h", 22)
	if err != nil {
		t.Fatal(err)
	}
	// Full, and both have connections: limit.
	_, err = m.Up(context.Background(), fake("c", "r"))
	if pe := asProto(t, err); pe.Code != proto.CodeLimit {
		t.Fatalf("%+v", pe)
	}
	// b has no connections now: it makes room for c (least recently used
	// without connections).
	s2.Close()
	s2.Done()
	if _, err := m.Up(context.Background(), fake("c", "r")); err != nil {
		t.Fatal(err)
	}
	if m.Status("b").State != proto.StateDown || m.Status("a").State != proto.StateUp || m.Count() != 2 {
		t.Fatal("wrong network evicted")
	}
	s1.Close()
	s1.Done()
}

func TestIdleNetworksGoDown(t *testing.T) {
	m := manager(netd.Limits{Idle: 200 * time.Millisecond})
	s, err := m.Dial(context.Background(), fake("busy", "r"), "h", 22)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Up(context.Background(), fake("quiet", "r")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := m.Reap(); n != 1 {
		t.Fatalf("reaped %d", n)
	}
	if m.Status("quiet").State != proto.StateDown || m.Status("busy").State != proto.StateUp {
		t.Fatal("wrong network reaped")
	}
	// Once its connection ends, the busy one is idle too.
	s.Close()
	s.Done()
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.RunReaper(ctx, 50*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for m.Status("busy").State != proto.StateDown {
		if time.Now().After(deadline) {
			t.Fatal("not reaped")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// --- The protocol over a real socket ----------------------------------------

type harness struct {
	sock string
	m    *netd.Manager
}

func serve(t *testing.T, l netd.Limits) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "netd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "netd.sock")
	ln, err := netd.Listen(sock, 0o600, -1)
	if err != nil {
		t.Fatal(err)
	}
	m := manager(l)
	srv := &netd.Server{M: m, Log: testLog(), Access: netd.Access{GID: -1}, Linger: 300 * time.Millisecond}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { ln.Close(); m.DownAll("test") })
	return &harness{sock: sock, m: m}
}

// call sends one request and returns the answer and the connection.
func (h *harness) call(t *testing.T, req any) (map[string]any, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	var line []byte
	if s, ok := req.(string); ok {
		line = []byte(s)
	} else {
		line, _ = json.Marshal(req)
	}
	if _, err := c.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(c)
	answer, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	var v map[string]any
	if err := json.Unmarshal(answer, &v); err != nil {
		t.Fatalf("answer %q: %v", answer, err)
	}
	return v, c, r
}

func code(v map[string]any) string {
	if v["ok"] == true {
		return "ok"
	}
	s, _ := v["code"].(string)
	return s
}

func TestProtocol(t *testing.T) {
	h := serve(t, netd.Limits{})
	v, _, _ := h.call(t, map[string]any{"v": 1, "op": "hello"})
	if v["ok"] != true || v["v"] != float64(1) || v["version"] == "" {
		t.Fatalf("%v", v)
	}
	for req, want := range map[string]string{
		`{"v":1,"op":"hello"`:                       "invalid",
		`{"v":2,"op":"hello"}`:                      "invalid",
		`{"op":"hello"}`:                            "invalid",
		`{"v":1,"op":"teleport"}`:                   "invalid",
		`{"v":1}`:                                   "invalid",
		`{"v":1,"op":"up"}`:                         "invalid",
		`{"v":1,"op":"status","network_id":"../x"}`: "invalid",
		`{"v":1,"op":"down","network_id":"nope"}`:   "ok",
		`{"v":1,"op":"list"}`:                       "ok",
		`{"v":1,"op":"up","network":{"id":"t","kind":"tailscale","revision":"r"}}`:                       "unsupported_kind",
		`{"v":1,"op":"dial","network":{"id":"z","kind":"zerotier","revision":"r"},"host":"h","port":22}`: "unsupported_kind",
	} {
		if v, _, _ := h.call(t, req); code(v) != want {
			t.Errorf("%s → %v (want %s)", req, v, want)
		}
	}
	// Too long.
	if v, _, _ := h.call(t, `{"v":1,"op":"hello","pad":"`+strings.Repeat("x", proto.MaxLine)+`"}`); code(v) != "invalid" {
		t.Errorf("long line: %v", v)
	}
	v, _, _ = h.call(t, map[string]any{"v": 1, "op": "status", "network_id": "nope"})
	if v["status"].(map[string]any)["state"] != "down" {
		t.Fatalf("%v", v)
	}
	// up / peers / list with the fake backend.
	v, _, _ = h.call(t, map[string]any{"v": 1, "op": "up", "network": fake("f", "r")})
	if v["status"].(map[string]any)["state"] != "up" {
		t.Fatalf("%v", v)
	}
	v, _, _ = h.call(t, map[string]any{"v": 1, "op": "peers", "network": fake("f", "r")})
	if len(v["peers"].([]any)) != 1 {
		t.Fatalf("%v", v)
	}
	v, _, _ = h.call(t, map[string]any{"v": 1, "op": "list"})
	if len(v["networks"].([]any)) != 1 {
		t.Fatalf("%v", v)
	}
}

func TestSocketMode(t *testing.T) {
	h := serve(t, netd.Limits{})
	fi, err := os.Stat(h.sock)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	// A live socket is not replaced.
	if _, err := netd.Listen(h.sock, 0o600, -1); err == nil {
		t.Fatal("replaced a live socket")
	}
	a := netd.Access{GID: -1}
	if !a.Allowed(uint32(os.Getuid()), 0, 1) || !a.Allowed(0, 0, 1) || a.Allowed(54321, 54321, 1) {
		t.Fatal("access")
	}
	a.UIDs = map[uint32]bool{54321: true}
	if !a.Allowed(54321, 1, 1) {
		t.Fatal("allowed uid")
	}
	a = netd.Access{GID: 4242}
	if !a.Allowed(5000, 4242, 1) || a.Allowed(5000, 1, 1) {
		t.Fatal("group")
	}
}

// site is a WireGuard site at 10.9.0.1 answering banner on port 22, and
// the spec of a network to it (the server's end: 10.9.0.2).
func site(t *testing.T, id, banner string) *proto.Spec {
	t.Helper()
	priv, _ := wg.GenerateKey()
	s, err := wgtest.NewSite(wgtest.SiteConfig{
		Addr: "10.9.0.1", PeerPublic: priv.PublicKey(), PeerAllowed: []string{"10.9.0.2/32"}, Log: testLog(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Echo(22, banner); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(map[string]any{
		"addresses": []string{"10.9.0.2/32"},
		"peers": []map[string]any{{
			"public_key": s.Public.String(), "endpoint": fmt.Sprintf("127.0.0.1:%d", s.Port),
			"allowed_ips": []string{"10.9.0.0/24"},
		}},
	})
	sec, _ := json.Marshal(map[string]any{"private_key": priv.String()})
	return &proto.Spec{ID: id, Name: id, Kind: "wireguard", Revision: "r1", Config: cfg, Secret: sec, VaultID: "v-" + id}
}

func dialReq(spec *proto.Spec, host string, port int) map[string]any {
	return map[string]any{"v": 1, "op": "dial", "network": spec, "host": host, "port": port, "timeout_ms": 10000}
}

// Two networks with the same addresses (10.9.0.0/24) reach their own site
// only: one isolated node per network.
func TestDialThroughWireGuardAndIsolation(t *testing.T) {
	h := serve(t, netd.Limits{})
	a := site(t, "net-a", "site-A\n")
	b := site(t, "net-b", "site-B\n")
	for _, tc := range []struct {
		spec *proto.Spec
		want string
	}{{a, "site-A\n"}, {b, "site-B\n"}, {a, "site-A\n"}} {
		v, c, r := h.call(t, dialReq(tc.spec, "10.9.0.1", 22))
		if v["ok"] != true || v["remote"] != "10.9.0.1:22" {
			t.Fatalf("%v", v)
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		got, err := r.ReadString('\n')
		if err != nil || got != tc.want {
			t.Fatalf("%s: %q %v", tc.spec.ID, got, err)
		}
		// Echo, then half-close: the site sees EOF and closes, we read EOF.
		if _, err := c.Write([]byte("ping\n")); err != nil {
			t.Fatal(err)
		}
		if got, _ := r.ReadString('\n'); got != "ping\n" {
			t.Fatalf("echo %q", got)
		}
		if err := c.(*net.UnixConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if rest, err := io.ReadAll(r); err != nil || len(rest) != 0 {
			t.Fatalf("after half-close: %q %v", rest, err)
		}
	}
	// A network without that range cannot reach it.
	other := site(t, "net-c", "site-C\n")
	var cfg map[string]any
	_ = json.Unmarshal(other.Config, &cfg)
	cfg["peers"].([]any)[0].(map[string]any)["allowed_ips"] = []string{"10.8.0.0/24"}
	other.Config, _ = json.Marshal(cfg)
	if v, _, _ := h.call(t, dialReq(other, "10.9.0.1", 22)); code(v) != "dial_failed" {
		t.Fatalf("%v", v)
	}
	// Status shows the node, the traffic and the handshake.
	v, _, _ := h.call(t, map[string]any{"v": 1, "op": "status", "network_id": "net-a"})
	st := v["status"].(map[string]any)
	if st["state"] != "up" || st["rx_bytes"].(float64) == 0 || st["last_handshake_at"] == nil || st["dials"].(float64) != 2 {
		t.Fatalf("%v", st)
	}
	if st["node"].(map[string]any)["public_key"] == "" {
		t.Fatalf("%v", st)
	}
	if !strings.Contains(fmt.Sprint(st), "10.9.0.2/32") {
		t.Fatalf("%v", st)
	}
	// down closes open connections.
	_, c, r := h.call(t, dialReq(a, "10.9.0.1", 22))
	if got, _ := r.ReadString('\n'); got != "site-A\n" {
		t.Fatal(got)
	}
	if v, _, _ := h.call(t, map[string]any{"v": 1, "op": "down", "network_id": "net-a"}); v["ok"] != true {
		t.Fatal(v)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("connection not closed by down: %v", err)
	}
	if v, _, _ := h.call(t, map[string]any{"v": 1, "op": "status", "network_id": "net-a"}); v["status"].(map[string]any)["state"] != "down" {
		t.Fatal(v)
	}
}

// A peer that never answers: the dial times out with a hint.
func TestDialTimeout(t *testing.T) {
	h := serve(t, netd.Limits{})
	priv, _ := wg.GenerateKey()
	peer, _ := wg.GenerateKey()
	// A UDP port nobody answers on.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	cfg, _ := json.Marshal(map[string]any{
		"addresses": []string{"10.9.0.2/32"},
		"peers": []map[string]any{{
			"public_key": peer.PublicKey().String(), "endpoint": pc.LocalAddr().String(),
			"allowed_ips": []string{"10.9.0.0/24"},
		}},
	})
	sec, _ := json.Marshal(map[string]any{"private_key": priv.String()})
	spec := &proto.Spec{ID: "silent", Kind: "wireguard", Revision: "r", Config: cfg, Secret: sec}
	req := dialReq(spec, "10.9.0.1", 22)
	req["timeout_ms"] = 1500
	started := time.Now()
	v, _, _ := h.call(t, req)
	if code(v) != "timeout" || !strings.Contains(v["message"].(string), "handshake") {
		t.Fatalf("%v", v)
	}
	if d := time.Since(started); d < time.Second || d > 10*time.Second {
		t.Fatalf("took %s", d)
	}
	// Bad configuration: network_error, without the key in the message.
	bad := *spec
	bad.ID = "bad"
	bad.Secret = json.RawMessage(`{"private_key":"short"}`)
	v, _, _ = h.call(t, dialReq(&bad, "10.9.0.1", 22))
	if code(v) != "network_error" || strings.Contains(v["message"].(string), "short") {
		t.Fatalf("%v", v)
	}
}

// A client that goes away from a connection whose peer vanished (no FIN
// ever comes back) does not leave it open: the network can go idle.
func TestVanishedPeerDoesNotKeepTheConnection(t *testing.T) {
	h := serve(t, netd.Limits{})
	v, c, _ := h.call(t, dialReq(fake("gone", "r"), "blackhole", 22))
	if v["ok"] != true {
		t.Fatal(v)
	}
	if st := h.m.Status("gone"); st.Streams != 1 {
		t.Fatalf("%+v", st)
	}
	c.Close()
	// Not at once (the peer may still answer after a half-close), but after
	// the linger time without bytes.
	time.Sleep(100 * time.Millisecond)
	if st := h.m.Status("gone"); st.Streams != 1 {
		t.Fatalf("closed before the linger time: %+v", st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.m.Status("gone").Streams != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("still open: %+v", h.m.Status("gone"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
