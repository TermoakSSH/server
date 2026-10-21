// termoak-wgpeer is a WireGuard peer in user space for tests and QA (the
// "remote site" a network reaches). It is not part of termoak-netd and is
// never shipped.
//
//	termoak-wgpeer -addr 10.9.0.1 [-listen-port N] [-forward 22=127.0.0.1:2222]... [-echo 7]
//
// It prints one JSON line when ready: {"public_key": "…", "port": N}. Then
// it reads commands on stdin, one per line:
//
//	peer <public key> <allowed ip>[,<allowed ip>...]   add (or update) a client
//	remove <public key>                                 remove a client
//	quit
//
// and answers "ok" or "error: …" on stdout. It stops at EOF on stdin.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/TermoakSSH/server/netd/internal/wg"
	"github.com/TermoakSSH/server/netd/internal/wgtest"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	addr := flag.String("addr", "10.9.0.1", "address inside the tunnel")
	port := flag.Int("listen-port", 0, "WireGuard UDP port (0: any)")
	key := flag.String("private-key", "", "private key (base64; default: a new one)")
	var forwards, echoes list
	flag.Var(&forwards, "forward", "port=host:port: connections to this port of the site go to host:port (repeatable)")
	flag.Var(&echoes, "echo", "port[=banner]: an echo service (repeatable)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var priv wg.Key
	if *key != "" {
		k, err := wg.ParseKey(*key)
		if err != nil {
			fail(err)
		}
		priv = k
	}
	// The site starts with no client; `peer` adds them.
	site, err := wgtest.NewSite(wgtest.SiteConfig{Addr: *addr, ListenPort: *port, Private: priv, Log: log, NoPeer: true})
	if err != nil {
		fail(err)
	}
	defer site.Close()
	for _, f := range forwards {
		p, target, ok := strings.Cut(f, "=")
		n, err := strconv.Atoi(p)
		if !ok || err != nil {
			fail(fmt.Errorf("invalid -forward %q", f))
		}
		if err := site.Forward(n, target); err != nil {
			fail(err)
		}
	}
	for _, e := range echoes {
		p, banner, _ := strings.Cut(e, "=")
		n, err := strconv.Atoi(p)
		if err != nil {
			fail(fmt.Errorf("invalid -echo %q", e))
		}
		if err := site.Echo(n, banner); err != nil {
			fail(err)
		}
	}
	ready, _ := json.Marshal(map[string]any{"public_key": site.Public.String(), "port": site.Port})
	fmt.Println(string(ready))

	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		var err error
		switch {
		case f[0] == "peer" && len(f) == 3:
			err = site.SetPeer(f[1], strings.Split(f[2], ","))
		case f[0] == "remove" && len(f) == 2:
			err = site.RemovePeer(f[1])
		case f[0] == "quit":
			return
		default:
			err = fmt.Errorf("unknown command %q", in.Text())
		}
		if err != nil {
			fmt.Println("error:", err)
		} else {
			fmt.Println("ok")
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "termoak-wgpeer:", err)
	os.Exit(1)
}
