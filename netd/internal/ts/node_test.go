//go:build tailscale

package ts

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/proto"
)

func testLog(t *testing.T) *slog.Logger {
	if os.Getenv("NETD_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startControl runs a test control server (testcontrol) with its own DERP
// and STUN on 127.0.0.1.
func startControl(t *testing.T, setup func(*testcontrol.Server)) (string, *testcontrol.Server) {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logger.Discard,
	}
	if setup != nil {
		setup(control)
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL, control
}

// startSite is a device of the tailnet with an echo server on port 22.
func startSite(t *testing.T, ctx context.Context, controlURL, authKey string) *tsnet.Server {
	t.Helper()
	s := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "site",
		Store:      new(mem.Store),
		Ephemeral:  true,
		AuthKey:    authKey,
		UserLogf:   logger.Discard,
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatal(err)
	}
	ln, err := s.Listen("tcp", ":22")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return s
}

func tsSpec(t *testing.T, id, controlURL, authKey string, extra map[string]any) *proto.Spec {
	cfg := map[string]any{"control_url": controlURL}
	for k, v := range extra {
		cfg[k] = v
	}
	var sec any
	if authKey != "" {
		sec = map[string]string{"auth_key": authKey}
	}
	return spec(t, id, cfg, sec)
}

func settle(t *testing.T, n netd.Node, want string) netd.NodeInfo {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	n.(netd.Settler).Settled(ctx)
	info := n.Info()
	if info.State != want {
		t.Fatalf("state %q (%s), want %q", info.State, info.Message, want)
	}
	return info
}

func echo(t *testing.T, c net.Conn, size int) {
	t.Helper()
	defer c.Close()
	data := make([]byte, size)
	_, _ = rand.Read(data)
	go func() { _, _ = c.Write(data) }()
	got := make([]byte, size)
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("echo: different bytes")
	}
}

func codeOf(err error) string {
	var pe *proto.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// One ephemeral node: up with MagicDNS, peers, dials by name and address
// through its own netstack, nothing outside the tailnet, logout and its
// scratch directory removed on Close.
func TestTailnet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	controlURL, _ := startControl(t, nil)
	site := startSite(t, ctx, controlURL, "")
	siteV4, _ := site.TailscaleIPs()

	b := &Backend{StateDir: t.TempDir()}
	n, err := b.Start(ctx, tsSpec(t, id, controlURL, "tskey-test", map[string]any{"tags": []string{"tag:termoak", "tag:qa"}}), testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	info := settle(t, n, proto.StateUp)
	if info.Node == nil || len(info.Node.Addresses) == 0 || info.Node.NodeID == "" ||
		!strings.HasPrefix(info.Node.DNSName, "termoak-48bfc431.") || info.Node.AuthURL != "" {
		t.Errorf("node %+v", info.Node)
	}
	if info.ControlURL != controlURL || info.Ephemeral == nil || !*info.Ephemeral || info.MagicDNSSuffix != "tail-scale.ts.net" {
		t.Errorf("info %+v", info)
	}

	// The site shows up among the peers (the netmap may take a moment).
	var peers []proto.Peer
	for i := 0; i < 100; i++ {
		if peers, err = n.Peers(ctx); err == nil && len(peers) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(peers) != 1 || peers[0].Name != "site" || peers[0].DNSName != "site.tail-scale.ts.net" ||
		len(peers[0].Addresses) == 0 || peers[0].Online == nil || peers[0].ID == "" {
		t.Fatalf("peers %+v", peers)
	}
	if pc := n.Info().PeerCount; pc == nil || *pc != 1 {
		t.Errorf("peer count %v", pc)
	}

	for _, host := range []string{"site", "site.tail-scale.ts.net", siteV4.String()} {
		c, err := n.Dial(ctx, host, 22)
		if err != nil {
			t.Fatalf("dial %s: %v", host, err)
		}
		echo(t, c, 256<<10)
	}
	// Never outside the tailnet (tsnet's own Dial would use the host's
	// network for these).
	for _, host := range []string{"127.0.0.1", "8.8.8.8", "localhost", "nosuchdevice"} {
		if _, err := n.Dial(ctx, host, 22); codeOf(err) != proto.CodeDialFailed {
			t.Errorf("dial %s: %v", host, err)
		}
	}
	// A refused port inside the tailnet fails (no listener on the site).
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	if _, err := n.Dial(dctx, "site", 23); err == nil {
		t.Error("dial to a closed port worked")
	}
	dcancel()

	dir := n.(*Node).dir
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("scratch dir kept: %v", err)
	}
	if _, err := n.Peers(ctx); err == nil {
		t.Error("peers after close")
	}
}

// Through the Manager: up waits for the node to settle, status shows the
// Tailscale fields, dials and the per-kind limit.
func TestManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	controlURL, _ := startControl(t, nil)
	startSite(t, ctx, controlURL, "")

	b := &Backend{StateDir: t.TempDir()}
	netd.Register("tailscale", b)
	limits := netd.DefaultLimits()
	limits.StartTimeout = 60 * time.Second
	limits.KindMax = map[string]int{"tailscale": 1}
	m := netd.NewManager(limits, testLog(t))
	defer m.DownAll("test")

	st, err := m.Up(ctx, tsSpec(t, id, controlURL, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if st.State != proto.StateUp || st.ControlURL != controlURL || st.Ephemeral == nil || st.Node == nil || st.Node.DNSName == "" {
		t.Fatalf("status %+v", st)
	}
	var stream *netd.Stream
	for i := 0; i < 50; i++ {
		if stream, err = m.Dial(ctx, tsSpec(t, id, controlURL, "", nil), "site", 22); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	echo(t, stream.Conn, 64<<10)
	stream.Done()

	// A second Tailscale network replaces the idle first one (KindMax 1).
	other := "01a163bb-6c78-7573-addc-f7b8fd434c00"
	if _, err := m.Up(ctx, tsSpec(t, other, controlURL, "", nil)); err != nil {
		t.Fatal(err)
	}
	if s := m.Status(id); s.State != proto.StateDown {
		t.Errorf("first network still %s", s.State)
	}
	// With a connection open on it, a third one is refused.
	if stream, err = m.Dial(ctx, tsSpec(t, other, controlURL, "", nil), "site", 22); err != nil {
		t.Fatal(err)
	}
	defer stream.Done()
	if _, err := m.Up(ctx, tsSpec(t, id, controlURL, "", nil)); codeOf(err) != proto.CodeLimit {
		t.Errorf("over the limit: %v", err)
	}
}

// Without an auth key the node needs a login (the URL is reported, a dial
// says needs_auth/login at once); after the login it comes up.
func TestNeedsLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	controlURL, control := startControl(t, func(c *testcontrol.Server) { c.RequireAuth = true })

	b := &Backend{StateDir: t.TempDir()}
	n, err := b.Start(ctx, tsSpec(t, id, controlURL, "", nil), testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	info := settle(t, n, proto.StateNeedsAuth)
	if info.Auth != proto.AuthLogin || info.Node == nil || !strings.HasPrefix(info.Node.AuthURL, controlURL+"/auth/") {
		t.Fatalf("info %+v node %+v", info, info.Node)
	}

	netd.Register("tailscale", b)
	m := netd.NewManager(netd.DefaultLimits(), testLog(t))
	defer m.DownAll("test")
	other := "01a163bb-6c78-7573-addc-f7b8fd434c00"
	dctx, dcancel := context.WithTimeout(ctx, 60*time.Second)
	_, err = m.Dial(dctx, tsSpec(t, other, controlURL, "", nil), "site", 22)
	dcancel()
	var pe *proto.Error
	if !errors.As(err, &pe) || pe.Code != proto.CodeNeedsAuth || pe.Auth != proto.AuthLogin {
		t.Fatalf("dial: %#v", err)
	}
	if st := m.Status(other); st.State != proto.StateNeedsAuth || st.Auth != proto.AuthLogin || st.Node.AuthURL == "" {
		t.Errorf("status %+v", st)
	}

	if !control.CompleteAuth(info.Node.AuthURL) {
		t.Fatal("CompleteAuth")
	}
	for i := 0; i < 300 && n.Info().State != proto.StateUp; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if st := n.Info(); st.State != proto.StateUp || st.Node.AuthURL != "" || st.Auth != "" {
		t.Fatalf("after the login: %+v", st)
	}
}

// A control server that wants devices approved: needs_auth/approval.
func TestNeedsApproval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	controlURL, _ := startControl(t, func(c *testcontrol.Server) { c.RequireMachineAuth = true })
	b := &Backend{StateDir: t.TempDir()}
	n, err := b.Start(ctx, tsSpec(t, id, controlURL, "tskey-test", nil), testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	info := settle(t, n, proto.StateNeedsAuth)
	if info.Auth != proto.AuthApproval || info.Node.AuthURL != "" || !strings.Contains(info.Message, "approve") {
		t.Errorf("info %+v", info)
	}
}

// A key the control server refuses: error with a clear message (never the
// key itself).
func TestInvalidKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	controlURL, _ := startControl(t, func(c *testcontrol.Server) { c.RequireAuthKey = "tskey-good" })
	b := &Backend{StateDir: t.TempDir()}
	n, err := b.Start(ctx, tsSpec(t, id, controlURL, "tskey-wrongSECRET", nil), testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	info := settle(t, n, proto.StateError)
	if !strings.Contains(info.Message, "refused the auth key") || strings.Contains(info.Message, "SECRET") || info.LastError == "" {
		t.Errorf("info %+v", info)
	}
	n2, err := b.Start(ctx, tsSpec(t, "01a163bb-6c78-7573-addc-f7b8fd434c00", controlURL, "tskey-good", nil), testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Close()
	settle(t, n2, proto.StateUp)
}

// A persistent node keeps its identity across restarts; forgetting it
// logs it out and removes its state.
func TestPersistent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	controlURL, _ := startControl(t, nil)
	b := &Backend{StateDir: t.TempDir()}
	sp := tsSpec(t, id, controlURL, "tskey-test", map[string]any{"ephemeral": false})
	n, err := b.Start(ctx, sp, testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	first := settle(t, n, proto.StateUp)
	dir := n.(*Node).dir
	if dir != b.dirs().persistent(id) || first.Ephemeral == nil || *first.Ephemeral {
		t.Fatalf("dir %s info %+v", dir, first)
	}
	_ = n.Close()
	if !hasState(dir) {
		t.Fatal("the state was not kept")
	}
	// Without the key: the stored node is used.
	n, err = b.Start(ctx, tsSpec(t, id, controlURL, "", map[string]any{"ephemeral": false}), testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	again := settle(t, n, proto.StateUp)
	if again.Node.NodeID != first.Node.NodeID || again.Node.Addresses[0] != first.Node.Addresses[0] {
		t.Errorf("another node: %+v vs %+v", again.Node, first.Node)
	}
	_ = n.Close()
	if err := b.Forget(ctx, id, testLog(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("state kept after forget: %v", err)
	}
	// Running and forgotten (down with forget).
	n, err = b.Start(ctx, sp, testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	settle(t, n, proto.StateUp)
	if err := n.(netd.ForgetCloser).CloseAndForget(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("state kept after CloseAndForget: %v", err)
	}
}
