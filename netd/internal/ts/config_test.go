package ts

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TermoakSSH/server/netd/internal/proto"
)

func spec(t *testing.T, id string, cfg, secret any) *proto.Spec {
	t.Helper()
	s := &proto.Spec{ID: id, Name: "Office", Kind: "tailscale", Revision: "r1"}
	if cfg != nil {
		b, _ := json.Marshal(cfg)
		s.Config = b
	}
	if secret != nil {
		b, _ := json.Marshal(secret)
		s.Secret = b
	}
	return s
}

const id = "01a163bb-6c74-73bc-96bc-6d9c48bfc431"

func TestDefaults(t *testing.T) {
	p, err := parse(spec(t, id, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.hostname != "termoak-48bfc431" {
		t.Errorf("hostname %q", p.hostname)
	}
	if len(p.tags) != 0 {
		t.Errorf("tags %v (the auth key's tags apply)", p.tags)
	}
	// An OAuth client secret needs tags: tag:termoak by default.
	p2, err := parse(spec(t, id, nil, map[string]string{"auth_key": "tskey-client-abc-def?ephemeral=true"}))
	if err != nil || strings.Join(p2.tags, ",") != "tag:termoak" {
		t.Errorf("oauth tags %v %v", p2.tags, err)
	}
	// Without a key the node is persistent (a login by hand is kept).
	if p.ephemeral || p.controlURL != "" || p.authKey != "" {
		t.Errorf("plan %+v", p)
	}
	if p.effectiveControlURL() != DefaultControlURL {
		t.Errorf("control %q", p.effectiveControlURL())
	}
	// Networks created in the same minute differ (the end of a UUIDv7 is random).
	if DefaultHostname("01a163bb-6c74-73bc-96bc-6d9c48bfc431") == DefaultHostname("01a163bb-6c78-7573-addc-f7b8fd434c00") {
		t.Error("default hostnames of close ids collide")
	}
	if DefaultHostname("") != "termoak" {
		t.Error("empty id")
	}
}

func TestConfig(t *testing.T) {
	cfg := map[string]any{
		"control_url": " https://headscale.example.com/ ",
		"hostname":    "Termoak-Office",
		"tags":        []string{"tag:termoak", "tag:prod", "tag:prod", " "},
		"ephemeral":   false,
	}
	p, err := parse(spec(t, id, cfg, map[string]string{"auth_key": " hskey-auth-abc_DEF-123 "}))
	if err != nil {
		t.Fatal(err)
	}
	if p.controlURL != "https://headscale.example.com" || p.hostname != "termoak-office" || p.ephemeral {
		t.Errorf("plan %+v", p)
	}
	if strings.Join(p.tags, ",") != "tag:termoak,tag:prod" {
		t.Errorf("tags %v", p.tags)
	}
	if p.authKey != "hskey-auth-abc_DEF-123" {
		t.Error("auth key not trimmed")
	}
	// null fields are the defaults.
	p, err = parse(spec(t, id, map[string]any{"control_url": nil, "hostname": nil, "tags": nil, "ephemeral": nil}, map[string]string{"auth_key": "k"}))
	if err != nil || !p.ephemeral || p.hostname != "termoak-48bfc431" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestInvalidConfig(t *testing.T) {
	const key = "tskey-auth-SECRET123"
	cases := []struct {
		cfg    map[string]any
		secret map[string]string
		want   string
	}{
		{map[string]any{"control_url": "ftp://x"}, nil, "control URL"},
		{map[string]any{"control_url": "https://"}, nil, "control URL"},
		{map[string]any{"control_url": "https://u:p@hs.example.com"}, nil, "user or password"},
		{map[string]any{"control_url": "https://hs.example.com/?a=1"}, nil, "query"},
		{map[string]any{"hostname": "-bad"}, nil, "hostname"},
		{map[string]any{"hostname": "has space"}, nil, "hostname"},
		{map[string]any{"hostname": strings.Repeat("a", 64)}, nil, "hostname"},
		{map[string]any{"tags": []string{"termoak"}}, nil, "tag"},
		{map[string]any{"tags": []string{"tag:"}}, nil, "tag"},
		{map[string]any{"tags": []string{"tag:a b"}}, nil, "tag"},
		{nil, map[string]string{"auth_key": key + " x"}, "auth key"},
		{nil, map[string]string{"auth_key": key + "\n"}, ""}, // trimmed: fine
		{nil, map[string]string{"auth_key": strings.Repeat("k", 2000)}, "too long"},
		{map[string]any{"tags": "tag:x"}, nil, "configuration"},
	}
	for i, c := range cases {
		var sec any
		if c.secret != nil {
			sec = c.secret
		}
		var cfg any
		if c.cfg != nil {
			cfg = c.cfg
		}
		_, err := parse(spec(t, id, cfg, sec))
		if c.want == "" {
			if err != nil {
				t.Errorf("%d: unexpected %v", i, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%d: got %v, want %q", i, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%d: the error echoes the key: %v", i, err)
		}
	}
	s := spec(t, id, nil, nil)
	s.Secret = json.RawMessage(`"tskey-auth-SECRET123"`)
	if _, err := parse(s); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("bad secret: %v", err)
	}
}

func TestMapState(t *testing.T) {
	cases := []struct {
		v           view
		state, auth string
		msg         string
	}{
		{view{backend: bsNoState, hasKey: true}, proto.StateStarting, "", "control server"},
		{view{backend: bsNeedsLogin, hasKey: true}, proto.StateStarting, "", ""},
		{view{backend: bsStarting, hasKey: true}, proto.StateStarting, "", "joining"},
		{view{backend: bsRunning, lastErr: "old"}, proto.StateUp, "", ""},
		{view{backend: bsNeedsLogin, authURL: "https://login.tailscale.com/a/x"}, proto.StateNeedsAuth, proto.AuthLogin, "login URL"},
		{view{backend: bsNeedsLogin, authURL: "https://hs/register/x", hasKey: true}, proto.StateNeedsAuth, proto.AuthLogin, "auth key"},
		{view{backend: bsNeedsMachineAuth}, proto.StateNeedsAuth, proto.AuthApproval, "approve"},
		{view{backend: bsNeedsLogin, lastErr: "invalid key: unable to validate API key", hasKey: true}, proto.StateError, "", "refused the auth key"},
		{view{backend: bsNeedsLogin, lastErr: "connection refused"}, proto.StateError, "", "connection refused"},
		{view{backend: bsStopped}, proto.StateError, "", "stopped"},
		{view{backend: bsNeedsLogin, hasKey: true, lastErr: "handling register with auth key: creating new node: requested tags [tag:x] are invalid or not permitted"}, proto.StateError, "", "leave the tags empty"},
	}
	for i, c := range cases {
		m := mapState(c.v)
		if m.state != c.state || m.auth != c.auth || !strings.Contains(m.message, c.msg) {
			t.Errorf("%d: %+v → %+v", i, c.v, m)
		}
	}
}

func TestResolve(t *testing.T) {
	tn := &tailnet{
		routes: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.7/32"),
			netip.MustParsePrefix("fd7a:115c:a1e0::7/128"),
			netip.MustParsePrefix("192.168.10.0/24"), // a subnet router
		},
		names: map[string][]netip.Addr{
			"nas.tail1234.ts.net":     {netip.MustParseAddr("fd7a:115c:a1e0::7"), netip.MustParseAddr("100.64.0.7")},
			"shared.other.ts.net":     {netip.MustParseAddr("100.64.0.7")},
			"printer.tail1234.ts.net": {netip.MustParseAddr("100.64.0.99")}, // no route (stale)
		},
		suffix: "tail1234.ts.net",
	}
	ctx := context.Background()
	noLookup := func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("the system resolver was used")
		return nil, nil
	}
	for _, host := range []string{"nas", "NAS", "nas.tail1234.ts.net", "nas.tail1234.ts.net.", "shared"} {
		got, err := tn.resolve(ctx, host, noLookup)
		if err != nil || len(got) == 0 || !got[0].Is4() {
			t.Errorf("%s: %v %v", host, got, err)
		}
	}
	for _, host := range []string{"100.64.0.7", "[fd7a:115c:a1e0::7]", "192.168.10.5", "::ffff:100.64.0.7"} {
		if _, err := tn.resolve(ctx, host, noLookup); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	codeOf := func(err error) string {
		var pe *proto.Error
		if errors.As(err, &pe) {
			return pe.Code
		}
		return ""
	}
	// Outside the tailnet: the internet, the host's LAN, an exit route.
	for _, host := range []string{"8.8.8.8", "192.168.11.1", "127.0.0.1", "100.64.0.8", "printer", "unknown"} {
		_, err := tn.resolve(ctx, host, noLookup)
		if codeOf(err) != proto.CodeDialFailed {
			t.Errorf("%s: %v", host, err)
		}
	}
	// A public name resolved by the system: only kept if it is in the tailnet.
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "nas.example.com":
			return []netip.Addr{netip.MustParseAddr("100.64.0.7")}, nil
		case "www.example.com":
			return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
		}
		return nil, errors.New("no such host")
	}
	if got, err := tn.resolve(ctx, "nas.example.com", lookup); err != nil || got[0] != netip.MustParseAddr("100.64.0.7") {
		t.Errorf("public name: %v %v", got, err)
	}
	if _, err := tn.resolve(ctx, "www.example.com", lookup); codeOf(err) != proto.CodeDialFailed || !strings.Contains(err.Error(), "outside the tailnet") {
		t.Errorf("internet name: %v", err)
	}
	if _, err := tn.resolve(ctx, "nope.example.com", lookup); codeOf(err) != proto.CodeDialFailed {
		t.Errorf("unknown name: %v", err)
	}
	// /0 routes (an exit node) never make an address routed.
	exit := &tailnet{routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
	if exit.routed(netip.MustParseAddr("8.8.8.8")) {
		t.Error("an exit route made the internet routed")
	}
}

func TestStateDir(t *testing.T) {
	d := newStateDir(t.TempDir())
	a, err := d.scratch(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.scratch(id)
	if err != nil || a == b {
		t.Fatalf("scratch dirs %q %q %v", a, b, err)
	}
	if fi, err := os.Stat(a); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("scratch mode %v %v", fi, err)
	}
	p := d.persistent(id)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if hasState(p) {
		t.Error("empty dir has state")
	}
	if err := os.WriteFile(filepath.Join(p, stateFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasState(p) {
		t.Error("no state")
	}
	if err := writeMarker(p, marker{ControlURL: "https://hs.example.com"}); err != nil {
		t.Fatal(err)
	}
	if m, err := readMarker(p); err != nil || m.ControlURL != "https://hs.example.com" {
		t.Errorf("marker %+v %v", m, err)
	}
	n, err := d.cleanScratch()
	if err != nil || n != 2 {
		t.Errorf("cleaned %d %v", n, err)
	}
	if _, err := os.Stat(a); !os.IsNotExist(err) {
		t.Error("scratch dir kept")
	}
	if !hasState(p) {
		t.Error("the persistent state was cleaned")
	}
	if n, err := newStateDir(filepath.Join(t.TempDir(), "missing")).cleanScratch(); n != 0 || err != nil {
		t.Errorf("missing root: %d %v", n, err)
	}
}
