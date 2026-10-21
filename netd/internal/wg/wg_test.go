package wg_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/proto"
	"github.com/TermoakSSH/server/netd/internal/wg"
	"github.com/TermoakSSH/server/netd/internal/wgtest"
)

func testLog() *slog.Logger {
	if os.Getenv("NETD_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// pair is a site (10.9.0.1) and the spec of a network that reaches it as
// 10.9.0.2.
type pair struct {
	site *wgtest.Site
	spec *proto.Spec
	priv wg.Key
}

func newPair(t *testing.T, id string, extra func(cfg map[string]any)) *pair {
	t.Helper()
	priv, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	site, err := wgtest.NewSite(wgtest.SiteConfig{
		Addr:        "10.9.0.1",
		PeerPublic:  priv.PublicKey(),
		PeerAllowed: []string{"10.9.0.2/32"},
		Log:         testLog(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(site.Close)
	cfg := map[string]any{
		"addresses": []string{"10.9.0.2/32"},
		"peers": []map[string]any{{
			"public_key":           site.Public.String(),
			"endpoint":             fmt.Sprintf("127.0.0.1:%d", site.Port),
			"allowed_ips":          []string{"10.9.0.0/24"},
			"persistent_keepalive": nil,
		}},
	}
	if extra != nil {
		extra(cfg)
	}
	return &pair{site: site, spec: spec(id, cfg, map[string]any{"private_key": priv.String()}), priv: priv}
}

func spec(id string, cfg, secret map[string]any) *proto.Spec {
	c, _ := json.Marshal(cfg)
	s, _ := json.Marshal(secret)
	return &proto.Spec{ID: id, Name: "net " + id, Kind: "wireguard", Revision: "r1", Config: c, Secret: s}
}

func start(t *testing.T, s *proto.Spec) netd.Node {
	t.Helper()
	node, err := (&wg.Backend{}).Start(context.Background(), s, testLog())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func dial(t *testing.T, node netd.Node, host string, port int) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := node.Dial(ctx, host, port)
	if err != nil {
		t.Fatalf("dial %s:%d: %v", host, port, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readN(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	buf := make([]byte, n)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

func TestDialThroughTheTunnel(t *testing.T) {
	p := newPair(t, "n1", nil)
	if err := p.site.Echo(22, "SSH-2.0-site\r\n"); err != nil {
		t.Fatal(err)
	}
	node := start(t, p.spec)
	c := dial(t, node, "10.9.0.1", 22)
	if got := readN(t, c, 14); got != "SSH-2.0-site\r\n" {
		t.Fatalf("banner %q", got)
	}
	// 4 MiB both ways, checked.
	data := make([]byte, 4<<20)
	_, _ = rand.Read(data)
	go func() { _, _ = c.Write(data) }()
	got := make([]byte, len(data))
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatal("the echoed data differs")
	}
	info := node.Info()
	if info.State != proto.StateUp || info.LastHandshakeAt == 0 || info.RxBytes == 0 || info.TxBytes == 0 {
		t.Fatalf("info %+v", info)
	}
	if info.Node.PublicKey != p.priv.PublicKey().String() || info.Node.Addresses[0] != "10.9.0.2/32" {
		t.Fatalf("node %+v", info.Node)
	}
	peers, _ := node.Peers(context.Background())
	if len(peers) != 1 || peers[0].Online == nil || !*peers[0].Online || peers[0].Addresses[0] != "10.9.0.0/24" {
		t.Fatalf("peers %+v", peers)
	}
	if !p.site.Handshakes() {
		t.Fatal("the site saw no handshake")
	}
}

func TestOutsideTheNetworkFailsAtOnce(t *testing.T) {
	p := newPair(t, "n2", nil)
	node := start(t, p.spec)
	started := time.Now()
	_, err := node.Dial(context.Background(), "10.8.0.1", 22)
	var pe *proto.Error
	if !errors.As(err, &pe) || pe.Code != proto.CodeDialFailed {
		t.Fatalf("err %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("took too long")
	}
	// A public name without DNS servers resolves with the system resolver,
	// and its address is outside the network as well.
	if _, err := node.Dial(context.Background(), "localhost", 22); !errors.As(err, &pe) || pe.Code != proto.CodeDialFailed {
		t.Fatalf("localhost: %v", err)
	}
}

func TestClosedPortIsRefused(t *testing.T) {
	p := newPair(t, "n3", nil)
	node := start(t, p.spec)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := node.Dial(ctx, "10.9.0.1", 2222); err == nil || ctx.Err() != nil {
		t.Fatalf("expected a refusal before the deadline, got %v", err)
	}
}

func TestNamesResolveWithTheNetworksDNS(t *testing.T) {
	p := newPair(t, "n4", func(cfg map[string]any) {
		cfg["dns"] = []string{"10.9.0.1", "lan"}
	})
	if err := p.site.DNS(map[string]string{"nas.lan": "10.9.0.1", "far.lan": "192.168.77.1"}); err != nil {
		t.Fatal(err)
	}
	if err := p.site.Echo(22, "hi"); err != nil {
		t.Fatal(err)
	}
	node := start(t, p.spec)
	for _, name := range []string{"nas.lan", "nas", "NAS.lan."} {
		c := dial(t, node, name, 22)
		if got := readN(t, c, 2); got != "hi" {
			t.Fatalf("%s: %q", name, got)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var pe *proto.Error
	if _, err := node.Dial(ctx, "missing.lan", 22); !errors.As(err, &pe) || pe.Code != proto.CodeDialFailed {
		t.Fatalf("missing: %v", err)
	}
	if _, err := node.Dial(ctx, "far.lan", 22); !errors.As(err, &pe) || !bytes.Contains([]byte(pe.Message), []byte("outside the network")) {
		t.Fatalf("far: %v", err)
	}
}

func TestInvalidConfigurations(t *testing.T) {
	key, _ := wg.GenerateKey()
	good := func() (map[string]any, map[string]any) {
		return map[string]any{
			"addresses": []string{"10.9.0.2/32"},
			"peers":     []map[string]any{{"public_key": key.PublicKey().String(), "allowed_ips": []string{"10.9.0.0/24"}}},
		}, map[string]any{
			"private_key": key.String(),
		}
	}
	cases := map[string]func(cfg, sec map[string]any){
		"no private key":  func(cfg, sec map[string]any) { delete(sec, "private_key") },
		"bad private key": func(cfg, sec map[string]any) { sec["private_key"] = "abc" },
		"bad psk":         func(cfg, sec map[string]any) { sec["preshared_key"] = "abc" },
		"no address":      func(cfg, sec map[string]any) { cfg["addresses"] = []string{} },
		"bad address":     func(cfg, sec map[string]any) { cfg["addresses"] = []string{"10.9.0"} },
		"no peers":        func(cfg, sec map[string]any) { cfg["peers"] = []any{} },
		"bad peer key": func(cfg, sec map[string]any) {
			cfg["peers"] = []map[string]any{{"public_key": "x"}}
		},
		"bad endpoint": func(cfg, sec map[string]any) {
			cfg["peers"] = []map[string]any{{"public_key": key.PublicKey().String(), "endpoint": "nowhere"}}
		},
		"bad mtu": func(cfg, sec map[string]any) { cfg["mtu"] = 100 },
	}
	for name, change := range cases {
		cfg, sec := good()
		change(cfg, sec)
		_, err := (&wg.Backend{}).Start(context.Background(), spec("bad", cfg, sec), testLog())
		if err == nil {
			t.Errorf("%s: started", name)
		} else if bytes.Contains([]byte(err.Error()), []byte(key.String())) {
			t.Errorf("%s: the error shows the private key", name)
		}
	}
	// The good one starts (no endpoint: it waits for the peer).
	cfg, sec := good()
	node, err := (&wg.Backend{}).Start(context.Background(), spec("good", cfg, sec), testLog())
	if err != nil {
		t.Fatal(err)
	}
	_ = node.Close()
	_ = node.Close() // twice is fine
}

func TestKeys(t *testing.T) {
	k, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	back, err := wg.ParseKey(k.String())
	if err != nil || back != k {
		t.Fatal("round trip")
	}
	// RFC 7748 test vector (Alice).
	priv, _ := wg.ParseKey("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=")
	if got := priv.PublicKey().String(); got != "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" {
		t.Fatalf("public key %s", got)
	}
}
