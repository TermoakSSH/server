//go:build tailscale

// termoak-tsnode is a Tailscale node in user space for tests and QA (the
// "remote site" a Tailscale/Headscale network reaches): a tsnet node whose
// ports forward to local addresses. It is not part of termoak-netd and is
// never shipped. Build: go build -tags tailscale ./cmd/termoak-tsnode
//
//	termoak-tsnode -control-url http://127.0.0.1:8080 -hostname ssh-site \
//	  [-tags tag:site] [-forward 22=127.0.0.1:2222]... [-echo 7]... [-state-dir DIR]
//
// The auth key comes from TS_AUTHKEY. It prints one JSON line when it is
// up: {"hostname": "…", "dns_name": "…", "addresses": ["100.64.0.1", …]}
// and runs until SIGINT/SIGTERM or EOF on stdin; then it logs out (an
// ephemeral node is deleted by the control server).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/logtail"
	"tailscale.com/tsnet"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	logtail.Disable()
	control := flag.String("control-url", "", "control server (Headscale URL; empty: Tailscale)")
	hostname := flag.String("hostname", "ssh-site", "node name")
	tags := flag.String("tags", "", "ACL tags to advertise (comma separated)")
	stateDir := flag.String("state-dir", "", "directory for tsnet's files (default: a temporary one)")
	verbose := flag.Bool("v", false, "tsnet logs on stderr")
	var forwards, echoes list
	flag.Var(&forwards, "forward", "port=host:port: connections to this port of the node go to host:port (repeatable)")
	flag.Var(&echoes, "echo", "port: an echo service (repeatable)")
	flag.Parse()

	dir := *stateDir
	if dir == "" {
		d, err := os.MkdirTemp("", "termoak-tsnode")
		if err != nil {
			fail(err)
		}
		defer os.RemoveAll(d)
		dir = d
	}
	s := &tsnet.Server{
		Dir:        dir,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Hostname:   *hostname,
		ControlURL: *control,
		AuthKey:    os.Getenv("TS_AUTHKEY"),
		UserLogf:   func(string, ...any) {},
	}
	if *tags != "" {
		s.AdvertiseTags = strings.Split(*tags, ",")
	}
	if *verbose {
		s.Logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
		s.UserLogf = s.Logf
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	st, err := s.Up(ctx)
	cancel()
	if err != nil {
		fail(err)
	}
	for _, f := range forwards {
		p, target, ok := strings.Cut(f, "=")
		if _, err := strconv.Atoi(p); !ok || err != nil {
			fail(fmt.Errorf("invalid -forward %q", f))
		}
		ln, err := s.Listen("tcp", ":"+p)
		if err != nil {
			fail(err)
		}
		go serve(ln, func(c net.Conn) {
			t, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				return
			}
			defer t.Close()
			go func() { _, _ = io.Copy(t, c); closeWrite(t) }()
			_, _ = io.Copy(c, t)
			closeWrite(c)
		})
	}
	for _, p := range echoes {
		ln, err := s.Listen("tcp", ":"+p)
		if err != nil {
			fail(err)
		}
		go serve(ln, func(c net.Conn) { _, _ = io.Copy(c, c) })
	}
	addrs := []string{}
	for _, a := range st.TailscaleIPs {
		addrs = append(addrs, a.String())
	}
	dns := ""
	if st.Self != nil {
		dns = strings.TrimSuffix(st.Self.DNSName, ".")
	}
	ready, _ := json.Marshal(map[string]any{"hostname": *hostname, "dns_name": dns, "addresses": addrs})
	fmt.Println(string(ready))

	done := make(chan struct{})
	go func() {
		// EOF on stdin (the test harness went away) stops it too.
		_, _ = io.Copy(io.Discard, bufio.NewReader(os.Stdin))
		close(done)
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case <-done:
	}
	if lc, err := s.LocalClient(); err == nil {
		lctx, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = lc.Logout(lctx)
		lcancel()
	}
	_ = s.Close()
}

func serve(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			handle(c)
		}()
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "termoak-tsnode:", err)
	os.Exit(1)
}
