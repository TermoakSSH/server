package ts

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/TermoakSSH/server/netd/internal/proto"
)

// tailnet is what a dial may reach in a tailnet.
type tailnet struct {
	// routes: the peers' addresses and the subnets they route (exit
	// routes, /0, are never kept).
	routes []netip.Prefix
	// names: MagicDNS names (FQDN, lowercase, no final dot) and the
	// tailnet's extra DNS records.
	names map[string][]netip.Addr
	// suffix: the MagicDNS suffix (tail1234.ts.net).
	suffix string
}

// routed tells whether a dial to addr stays inside the tailnet.
func (t *tailnet) routed(addr netip.Addr) bool {
	for _, r := range t.routes {
		if r.Bits() > 0 && r.Contains(addr) {
			return true
		}
	}
	return false
}

// lookupFunc is net.Resolver.LookupNetIP (the system resolver).
type lookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// resolve finds the tailnet addresses of host: an IP as is; a MagicDNS
// name (nas, nas.tail1234.ts.net) from the node's network map; any other
// name with the system resolver. Only addresses inside the tailnet are
// kept (IPv4 first); anything else fails at once with dial_failed.
func (t *tailnet) resolve(ctx context.Context, host string, lookup lookupFunc) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		a = a.Unmap()
		if !t.routed(a) {
			return nil, proto.Errorf(proto.CodeDialFailed, "%s is outside the tailnet (no device has that address or routes its subnet)", a)
		}
		return []netip.Addr{a}, nil
	}
	var found []netip.Addr
	candidates := []string{host}
	if t.suffix != "" && !strings.HasSuffix(host, "."+t.suffix) {
		candidates = append(candidates, host+"."+t.suffix)
	}
	for _, c := range candidates {
		if list := t.names[c]; len(list) > 0 {
			found = list
			break
		}
	}
	if len(found) == 0 && !strings.Contains(host, ".") {
		// A short name of a device in another tailnet's domain (shared
		// devices): match the first label.
		var match []string
		for name := range t.names {
			if first, _, _ := strings.Cut(name, "."); first == host {
				match = append(match, name)
			}
		}
		if len(match) == 1 {
			found = t.names[match[0]]
		}
	}
	if len(found) == 0 {
		if lookup == nil || !strings.Contains(host, ".") {
			return nil, proto.Errorf(proto.CodeDialFailed, "there is no device named %s in the tailnet (or it is not shared with the server's node)", host)
		}
		list, err := lookup(ctx, "ip", host)
		if err != nil {
			return nil, proto.Errorf(proto.CodeDialFailed, "%s is not a device of the tailnet and could not be resolved: %s", host, err)
		}
		for _, a := range list {
			found = append(found, a.Unmap())
		}
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, a := range found {
		a = a.Unmap()
		if t.routed(a) && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, proto.Errorf(proto.CodeDialFailed, "%s resolves to %s, which is outside the tailnet", host, found[0])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Is4() && !out[j].Is4() })
	return out, nil
}
