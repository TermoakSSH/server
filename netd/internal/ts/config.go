// Package ts joins Tailscale tailnets and Headscale servers with tsnet, in
// user space (gVisor netstack: no TUN device, no root, no routes). Every
// network is its own tsnet node with its own state and stack.
//
// This file (configuration, state mapping and the state directory) builds
// without tsnet; the backend itself (node.go) needs the `tailscale` build
// tag.
package ts

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/TermoakSSH/server/netd/internal/proto"
)

// DefaultControlURL is Tailscale's control server (a network without
// control_url).
const DefaultControlURL = "https://controlplane.tailscale.com"

// DefaultTag is the ACL tag the node asks for when it logs in with a
// Tailscale OAuth client secret (which needs tags) and the network names
// none. With an auth key and no tags the node gets the key's tags: create
// the key tagged (tag:termoak). Headscale (0.28+) refuses tags requested
// by a node that logs in with a pre-auth key; the key's tags apply.
const DefaultTag = "tag:termoak"

// oauthPrefix starts a Tailscale OAuth client secret.
const oauthPrefix = "tskey-client-"

// Config is Network.tailscale (the non-secret part).
type Config struct {
	// ControlURL: empty for Tailscale, the Headscale URL otherwise.
	ControlURL *string `json:"control_url"`
	// Hostname of the server's node (default termoak-<last 8 of the id>).
	Hostname *string `json:"hostname"`
	// Tags the node advertises. Empty: none (the auth key's tags apply);
	// tag:termoak with an OAuth client secret.
	Tags []string `json:"tags"`
	// Ephemeral: the node leaves the tailnet when it stops. Default: true
	// with an auth key; false without one (a node logged in by hand must
	// keep its login across restarts).
	Ephemeral *bool `json:"ephemeral"`
}

// Secret is NetworkSecret (the Tailscale field).
type Secret struct {
	// AuthKey: a pre-auth key (Tailscale tskey-auth-…, Headscale) or a
	// Tailscale OAuth client secret (tskey-client-…). Empty: interactive
	// login (needs_auth with the login URL).
	AuthKey string `json:"auth_key"`
}

// plan is a parsed, validated configuration.
type plan struct {
	id         string
	controlURL string // "" = Tailscale's (tsnet's default)
	hostname   string
	tags       []string
	ephemeral  bool
	authKey    string
}

// effectiveControlURL is what Status shows.
func (p *plan) effectiveControlURL() string {
	if p.controlURL == "" {
		return DefaultControlURL
	}
	return p.controlURL
}

var (
	hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tagPattern      = regexp.MustCompile(`^tag:[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
)

// DefaultHostname of a network's node: termoak-<last 8 hex digits of the
// id>. The ids are UUIDv7, whose first digits are a timestamp shared by
// networks created close together; the last ones are random.
func DefaultHostname(id string) string {
	var hex []rune
	for _, r := range strings.ToLower(id) {
		if unicode.IsDigit(r) || (r >= 'a' && r <= 'z') {
			hex = append(hex, r)
		}
	}
	if len(hex) > 8 {
		hex = hex[len(hex)-8:]
	}
	if len(hex) == 0 {
		return "termoak"
	}
	return "termoak-" + string(hex)
}

// ValidateControlURL checks a Headscale (or Tailscale) control URL.
func ValidateControlURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("invalid control URL %q (expected https://headscale.example.com)", raw)
	}
	if u.User != nil {
		return "", errors.New("the control URL cannot carry a user or password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the control URL cannot have a query or fragment")
	}
	return strings.TrimRight(raw, "/"), nil
}

// ValidateHostname checks a node name (a DNS label: lowercase letters,
// digits and dashes, up to 63).
func ValidateHostname(h string) error {
	if !hostnamePattern.MatchString(h) {
		return fmt.Errorf("invalid hostname %q (lowercase letters, digits and dashes, up to 63, like termoak-office)", h)
	}
	return nil
}

// ValidateTag checks an ACL tag (tag:name).
func ValidateTag(t string) error {
	if !tagPattern.MatchString(t) {
		return fmt.Errorf("invalid tag %q (expected tag:name with letters, digits, - and _)", t)
	}
	return nil
}

// ValidateAuthKey checks the shape of an auth key (not whether the control
// server takes it): printable ASCII without spaces.
func ValidateAuthKey(k string) error {
	if len(k) > 1024 {
		return errors.New("the auth key is too long")
	}
	for _, r := range k {
		if r <= ' ' || r > '~' {
			return errors.New("the auth key has spaces or characters that are not printable ASCII")
		}
	}
	return nil
}

// parse validates spec (never echoing the secret).
func parse(spec *proto.Spec) (*plan, error) {
	var cfg Config
	if len(spec.Config) > 0 && string(spec.Config) != "null" {
		if err := json.Unmarshal(spec.Config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid Tailscale configuration: %w", err)
		}
	}
	var sec Secret
	if len(spec.Secret) > 0 && string(spec.Secret) != "null" {
		if err := json.Unmarshal(spec.Secret, &sec); err != nil {
			return nil, errors.New("invalid Tailscale secret")
		}
	}
	p := &plan{id: spec.ID}
	if cfg.ControlURL != nil {
		u, err := ValidateControlURL(*cfg.ControlURL)
		if err != nil {
			return nil, err
		}
		p.controlURL = u
	}
	p.hostname = DefaultHostname(spec.ID)
	if cfg.Hostname != nil && strings.TrimSpace(*cfg.Hostname) != "" {
		h := strings.ToLower(strings.TrimSpace(*cfg.Hostname))
		if err := ValidateHostname(h); err != nil {
			return nil, err
		}
		p.hostname = h
	}
	seen := map[string]bool{}
	for _, t := range cfg.Tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if err := ValidateTag(t); err != nil {
			return nil, err
		}
		seen[t] = true
		p.tags = append(p.tags, t)
	}
	p.authKey = strings.TrimSpace(sec.AuthKey)
	if p.authKey != "" {
		if err := ValidateAuthKey(p.authKey); err != nil {
			return nil, err
		}
	}
	p.ephemeral = p.authKey != ""
	if cfg.Ephemeral != nil {
		p.ephemeral = *cfg.Ephemeral
	}
	if len(p.tags) == 0 && strings.HasPrefix(p.authKey, oauthPrefix) {
		// An OAuth client creates the node's key with these tags.
		p.tags = []string{DefaultTag}
	}
	return p, nil
}

// Backend states of tailscaled (ipn.State's names).
const (
	bsNoState          = "NoState"
	bsNeedsLogin       = "NeedsLogin"
	bsNeedsMachineAuth = "NeedsMachineAuth"
	bsStopped          = "Stopped"
	bsStarting         = "Starting"
	bsRunning          = "Running"
)

// view is what the node knows about itself, for mapState.
type view struct {
	backend string // ipn.State name
	authURL string // login URL, when the control server gave one
	lastErr string // latest error (control refused the key...)
	hasKey  bool   // the network has an auth key
}

// mapped is a node's state as netd reports it.
type mapped struct {
	state   string // proto.State*
	auth    string // proto.Auth* with StateNeedsAuth
	message string
}

// mapState turns tailscaled's backend state into netd's.
//
//   - Running → up.
//   - NeedsMachineAuth → needs_auth (approval): logged in, an admin must
//     approve the device.
//   - An error while not running (the control server refused the auth
//     key, could not be reached...) → error with it; tsnet keeps retrying,
//     so it may still come up.
//   - NeedsLogin with a login URL → needs_auth (login).
//   - Anything else (NoState, Starting, NeedsLogin while the auth key is
//     being used) → starting.
func mapState(v view) mapped {
	switch v.backend {
	case bsRunning:
		return mapped{state: proto.StateUp}
	case bsNeedsMachineAuth:
		return mapped{state: proto.StateNeedsAuth, auth: proto.AuthApproval,
			message: "the node is logged in but must be approved: approve it in the tailnet's admin console (Machines) or with headscale"}
	}
	if v.lastErr != "" {
		msg := v.lastErr
		if strings.Contains(msg, "requested tags") {
			msg = "the control server refused the node's tags (" + msg + "): leave the tags empty to use the auth key's tags (Headscale only takes the key's), or use tags the key's owner may assign"
		} else if v.hasKey && looksLikeKeyError(msg) {
			msg = "the control server refused the auth key: " + msg
		}
		return mapped{state: proto.StateError, message: msg}
	}
	if v.backend == bsStopped {
		return mapped{state: proto.StateError, message: "the node stopped"}
	}
	if v.backend == bsNeedsLogin && v.authURL != "" {
		msg := "the node must be logged in: open the login URL"
		if v.hasKey {
			msg = "the auth key was not enough to log the node in: open the login URL or use another key"
		}
		return mapped{state: proto.StateNeedsAuth, auth: proto.AuthLogin, message: msg}
	}
	msg := "connecting to the control server"
	if v.backend == bsStarting {
		msg = "joining the tailnet"
	}
	return mapped{state: proto.StateStarting, message: msg}
}

func looksLikeKeyError(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range []string{"key", "auth", "unauthorized", "401", "expired", "not valid", "invalid"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}
