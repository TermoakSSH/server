// termoak-netd joins the users' private networks for termoak-server, in
// user space, and opens connections inside them. Protocol and security
// model: docs/NETWORKS.md of the server repository.
//
//	termoak-netd [flags]                 serve on the socket
//	termoak-netd request '<json line>'   send one request and print the answer
//	termoak-netd version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TermoakSSH/server/netd/internal/netd"
	"github.com/TermoakSSH/server/netd/internal/wg"
)

func init() {
	// WireGuard is always built in (Tailscale: tailscale.go, behind the
	// `tailscale` build tag; ZeroTier: see netd.Backend).
	netd.Register("wireguard", &wg.Backend{})
}

// backendOptions are the command line options the backends need.
type backendOptions struct {
	// StateDir: where backends keep state (persistent Tailscale nodes).
	StateDir string
}

// backendSetup configures the backends after the flags are parsed (files
// behind build tags add theirs).
var backendSetup []func(backendOptions, *slog.Logger)

// defaultStateDir: systemd's StateDirectory= when set, else a directory
// in the temporary directory (lost on reboot).
func defaultStateDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		// systemd may list several, separated by ':'.
		d, _, _ = strings.Cut(d, ":")
		return d
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("termoak-netd-%d", os.Getuid()))
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		fmt.Fprintf(os.Stderr, "termoak-netd: ignoring %s=%q (not a duration like 15m)\n", name, v)
	}
	return def
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		fmt.Fprintf(os.Stderr, "termoak-netd: ignoring %s=%q (not a number)\n", name, v)
	}
	return def
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-V":
			fmt.Printf("termoak-netd %s (kinds: %s)\n", netd.Version, strings.Join(netd.Kinds(), ", "))
			return
		case "request":
			os.Exit(request(os.Args[2:]))
		}
	}
	os.Exit(serve(os.Args[1:]))
}

func serve(args []string) int {
	limits := netd.DefaultLimits()
	fs := flag.NewFlagSet("termoak-netd", flag.ExitOnError)
	socket := fs.String("socket", env("TERMOAK_NETD_SOCKET", "/run/termoak-netd/netd.sock"), "Unix socket to listen on (TERMOAK_NETD_SOCKET)")
	mode := fs.String("socket-mode", env("TERMOAK_NETD_SOCKET_MODE", ""), "socket mode: 0600 (default), or 0660 with -socket-group (TERMOAK_NETD_SOCKET_MODE)")
	group := fs.String("socket-group", env("TERMOAK_NETD_SOCKET_GROUP", ""), "group (name or gid) allowed to use the socket (TERMOAK_NETD_SOCKET_GROUP)")
	allowUIDs := fs.String("allow-uids", env("TERMOAK_NETD_ALLOW_UIDS", ""), "other users (uids or names, comma separated) allowed besides netd's own (TERMOAK_NETD_ALLOW_UIDS)")
	fs.DurationVar(&limits.Idle, "idle", envDuration("TERMOAK_NETD_IDLE", limits.Idle), "take a network down after this long without connections; 0 = never (TERMOAK_NETD_IDLE)")
	fs.IntVar(&limits.MaxNetworks, "max-networks", envInt("TERMOAK_NETD_MAX_NETWORKS", limits.MaxNetworks), "networks up at the same time (TERMOAK_NETD_MAX_NETWORKS)")
	fs.IntVar(&limits.MaxStreams, "max-streams", envInt("TERMOAK_NETD_MAX_STREAMS", limits.MaxStreams), "open connections per network (TERMOAK_NETD_MAX_STREAMS)")
	maxTailscale := fs.Int("max-tailscale", envInt("TERMOAK_NETD_MAX_TAILSCALE", limits.KindMax["tailscale"]), "Tailscale/Headscale nodes up at the same time (each takes 10-20 MiB) (TERMOAK_NETD_MAX_TAILSCALE)")
	stateDir := fs.String("state-dir", env("TERMOAK_NETD_STATE_DIR", defaultStateDir()), "state directory: persistent Tailscale nodes and the scratch files of ephemeral ones (TERMOAK_NETD_STATE_DIR; default systemd's STATE_DIRECTORY)")
	fs.DurationVar(&limits.MaxDialTimeout, "max-dial-timeout", envDuration("TERMOAK_NETD_MAX_DIAL_TIMEOUT", limits.MaxDialTimeout), "cap on a dial's timeout_ms (TERMOAK_NETD_MAX_DIAL_TIMEOUT)")
	logFormat := fs.String("log-format", env("TERMOAK_NETD_LOG_FORMAT", "text"), "text or json (TERMOAK_NETD_LOG_FORMAT)")
	logLevel := fs.String("log-level", env("TERMOAK_NETD_LOG_LEVEL", "info"), "debug, info, warn or error (TERMOAK_NETD_LOG_LEVEL)")
	_ = fs.Parse(args)

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "termoak-netd: invalid log level %q\n", *logLevel)
		return 2
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	log := slog.New(handler)

	access := netd.Access{UIDs: map[uint32]bool{}, GID: -1}
	gid := -1
	if *group != "" {
		g, err := lookupGroup(*group)
		if err != nil {
			log.Error("invalid socket group", "group", *group, "error", err)
			return 2
		}
		gid, access.GID = g, g
	}
	for _, u := range strings.Split(*allowUIDs, ",") {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		uid, err := lookupUser(u)
		if err != nil {
			log.Error("invalid user in -allow-uids", "user", u, "error", err)
			return 2
		}
		access.UIDs[uint32(uid)] = true
	}
	perm := os.FileMode(0o600)
	if gid >= 0 {
		perm = 0o660
	}
	if *mode != "" {
		m, err := strconv.ParseUint(*mode, 8, 32)
		if err != nil || m&^0o770 != 0 {
			log.Error("invalid socket mode (0600 or 0660)", "mode", *mode)
			return 2
		}
		perm = os.FileMode(m)
	}

	limits.KindMax = map[string]int{"tailscale": *maxTailscale}
	for _, setup := range backendSetup {
		setup(backendOptions{StateDir: *stateDir}, log)
	}

	ln, err := netd.Listen(*socket, perm, gid)
	if err != nil {
		log.Error("could not listen", "socket", *socket, "error", err)
		return 1
	}
	m := netd.NewManager(limits, log)
	srv := &netd.Server{M: m, Log: log, Access: access}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	tick := limits.Idle / 4
	if tick > 30*time.Second || tick <= 0 {
		tick = 30 * time.Second
	}
	if tick < time.Second {
		tick = time.Second
	}
	go m.RunReaper(ctx, tick)
	log.Info("termoak-netd listening", "version", netd.Version, "socket", *socket,
		"mode", fmt.Sprintf("%04o", perm), "kinds", netd.Kinds(), "idle", limits.Idle.String(),
		"max_networks", limits.MaxNetworks, "max_streams", limits.MaxStreams, "max_tailscale", *maxTailscale,
		"state_dir", *stateDir)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err := <-done:
		if err != nil {
			log.Error("serve failed", "error", err)
		}
	}
	log.Info("stopping: taking every network down")
	_ = ln.Close()
	m.DownAll("shutdown")
	srv.Wait(5 * time.Second)
	return 0
}

func lookupGroup(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

func lookupUser(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

// request sends one line (e.g. '{"v":1,"op":"list"}') and prints the
// answer: a health check for scripts and operators.
func request(args []string) int {
	fs := flag.NewFlagSet("termoak-netd request", flag.ExitOnError)
	socket := fs.String("socket", env("TERMOAK_NETD_SOCKET", "/run/termoak-netd/netd.sock"), "socket of termoak-netd")
	_ = fs.Parse(args)
	line := strings.Join(fs.Args(), " ")
	if line == "" {
		line = `{"v":1,"op":"hello"}`
	}
	c, err := net.DialTimeout("unix", *socket, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "termoak-netd: %v\n", err)
		return 1
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.WriteString(c, strings.TrimSpace(line)+"\n"); err != nil {
		fmt.Fprintf(os.Stderr, "termoak-netd: %v\n", err)
		return 1
	}
	answer, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "termoak-netd: %v\n", err)
		return 1
	}
	fmt.Print(answer)
	if strings.Contains(answer, `"ok":true`) {
		return 0
	}
	return 1
}
