//go:build tailscale

// The Tailscale/Headscale backend (tsnet), only in builds with
// `-tags tailscale` (the "with networks" bundle): without it, tailscale
// networks answer unsupported_kind and hello does not list the kind.

package main

import (
	"log/slog"
	"os"

	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/logtail"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/ts"
)

func init() {
	// tsnet uploads its logs to log.tailscale.com by default: never from
	// termoak-netd (they would name the users' tailnets and devices).
	logtail.Disable()
	envknob.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	hostinfo.SetApp("termoak-netd")
	backend := &ts.Backend{}
	netd.Register("tailscale", backend)
	backendSetup = append(backendSetup, func(o backendOptions, log *slog.Logger) {
		backend.StateDir = o.StateDir
		backend.Verbose = os.Getenv("TERMOAK_NETD_TAILSCALE_VERBOSE") == "1"
	})
}
