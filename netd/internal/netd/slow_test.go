package netd_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/proto"
)

// A backend whose nodes join in the background (like Tailscale): starting
// for a while, then up or waiting for a login; it keeps state that `down`
// with `forget` removes.
type slowBackend struct {
	mu        sync.Mutex
	forgotten []string // ids forgotten while not running
	dropped   []string // ids closed with CloseAndForget
}

var slow = &slowBackend{}

func init() { netd.Register("slow", slow) }

type slowNode struct {
	b       *slowBackend
	id      string
	login   bool
	settled chan struct{}
	fakeNode
}

func (b *slowBackend) Start(_ context.Context, spec *proto.Spec, _ *slog.Logger) (netd.Node, error) {
	n := &slowNode{b: b, id: spec.ID, login: strings.Contains(string(spec.Config), "login"), settled: make(chan struct{})}
	go func() { time.Sleep(150 * time.Millisecond); close(n.settled) }()
	return n, nil
}

func (b *slowBackend) Forget(_ context.Context, id string, _ *slog.Logger) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.forgotten = append(b.forgotten, id)
	return nil
}

func (n *slowNode) Settled(ctx context.Context) {
	select {
	case <-n.settled:
	case <-ctx.Done():
	}
}

func (n *slowNode) Info() netd.NodeInfo {
	select {
	case <-n.settled:
	default:
		return netd.NodeInfo{State: proto.StateStarting, Message: "joining"}
	}
	if n.login {
		return netd.NodeInfo{State: proto.StateNeedsAuth, Auth: proto.AuthLogin, Message: "log in",
			Node: &proto.Node{AuthURL: "https://hs.example.com/register/x"}, ControlURL: "https://hs.example.com"}
	}
	pc := 3
	return netd.NodeInfo{State: proto.StateUp, PeerCount: &pc, ControlURL: "https://hs.example.com", Tailnet: "qa"}
}

func (n *slowNode) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return n.fakeNode.Dial(ctx, host, port)
}

func (n *slowNode) CloseAndForget() error {
	n.b.mu.Lock()
	n.b.dropped = append(n.b.dropped, n.id)
	n.b.mu.Unlock()
	return n.Close()
}

func slowSpec(id, cfg string) *proto.Spec {
	s := fake(id, "r")
	s.Kind = "slow"
	s.Config = []byte(cfg)
	return s
}

func TestSettlingNodes(t *testing.T) {
	m := manager(netd.Limits{})
	defer m.DownAll("test")
	// up waits for the node to settle instead of answering starting.
	st, err := m.Up(context.Background(), slowSpec("a", `{}`))
	if err != nil || st.State != proto.StateUp || st.ControlURL != "https://hs.example.com" || st.PeerCount == nil || *st.PeerCount != 3 || st.Tailnet != "qa" {
		t.Fatalf("%+v %v", st, err)
	}
	// A dial waits too; a node that needs a login answers needs_auth with
	// the reason.
	_, err = m.Dial(context.Background(), slowSpec("b", `{"login":true}`), "h", 22)
	var pe *proto.Error
	if !errors.As(err, &pe) || pe.Code != proto.CodeNeedsAuth || pe.Auth != proto.AuthLogin {
		t.Fatalf("%#v", err)
	}
	if st := m.Status("b"); st.State != proto.StateNeedsAuth || st.Auth != proto.AuthLogin || st.Node.AuthURL == "" || st.DialsFailed != 1 {
		t.Fatalf("%+v", st)
	}
	// A dial that gives up while the node still joins: timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = m.Dial(ctx, slowSpec("c", `{}`), "h", 22)
	cancel()
	if !errors.As(err, &pe) || pe.Code != proto.CodeTimeout {
		t.Fatalf("%#v", err)
	}
	// The short wait of up answers starting.
	m2 := manager(netd.Limits{StartTimeout: 10 * time.Millisecond})
	defer m2.DownAll("test")
	if st, _ := m2.Up(context.Background(), slowSpec("d", `{}`)); st.State != proto.StateStarting {
		t.Fatalf("%+v", st)
	}
}

func TestKindLimit(t *testing.T) {
	m := manager(netd.Limits{KindMax: map[string]int{"slow": 1}})
	defer m.DownAll("test")
	s, err := m.Dial(context.Background(), slowSpec("a", `{}`), "h", 22)
	if err != nil {
		t.Fatal(err)
	}
	// Other kinds are not counted.
	if _, err := m.Up(context.Background(), fake("w", "r")); err != nil {
		t.Fatal(err)
	}
	_, err = m.Up(context.Background(), slowSpec("b", `{}`))
	if pe := asProto(t, err); pe.Code != proto.CodeLimit || !strings.Contains(pe.Message, "slow networks") {
		t.Fatalf("%+v", pe)
	}
	s.Close()
	s.Done()
	if _, err := m.Up(context.Background(), slowSpec("b", `{}`)); err != nil {
		t.Fatal(err)
	}
	if m.Status("a").State != proto.StateDown || m.Status("w").State != proto.StateUp {
		t.Fatal("wrong network evicted")
	}
}

func TestForget(t *testing.T) {
	h := serve(t, netd.Limits{})
	if _, err := h.m.Up(context.Background(), slowSpec("run", `{}`)); err != nil {
		t.Fatal(err)
	}
	// down with forget: the running node is closed with CloseAndForget,
	// and for a network that is not running every backend forgets it.
	for _, id := range []string{"run", "gone"} {
		if v, _, _ := h.call(t, map[string]any{"v": 1, "op": "down", "network_id": id, "forget": true}); code(v) != "ok" {
			t.Fatalf("%v", v)
		}
	}
	// A plain down forgets nothing.
	if _, err := h.m.Up(context.Background(), slowSpec("keep", `{}`)); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := h.call(t, map[string]any{"v": 1, "op": "down", "network_id": "keep"}); code(v) != "ok" {
		t.Fatalf("%v", v)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		slow.mu.Lock()
		dropped, forgotten := strings.Join(slow.dropped, ","), strings.Join(slow.forgotten, ",")
		slow.mu.Unlock()
		if dropped == "run" && forgotten == "gone" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dropped %q forgotten %q", dropped, forgotten)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h.m.Status("run").State != proto.StateDown || h.m.Status("keep").State != proto.StateDown {
		t.Fatal("still up")
	}
}

// needs_auth errors carry the reason on the protocol line.
func TestNeedsAuthLine(t *testing.T) {
	h := serve(t, netd.Limits{})
	v, _, _ := h.call(t, map[string]any{"v": 1, "op": "dial", "network": slowSpec("x", `{"login":1}`), "host": "h", "port": 22})
	if code(v) != proto.CodeNeedsAuth || v["auth"] != proto.AuthLogin {
		t.Fatalf("%v", v)
	}
	v, _, _ = h.call(t, map[string]any{"v": 1, "op": "status", "network_id": "x"})
	st, _ := v["status"].(map[string]any)
	if st["state"] != proto.StateNeedsAuth || st["auth"] != proto.AuthLogin || st["control_url"] != "https://hs.example.com" {
		t.Fatalf("%v", v)
	}
}
