// Package wgtest is a WireGuard peer in user space for tests and QA: "the
// other end of the tunnel" (a remote site) with its own netstack, where
// tests run TCP services (echo, forward to a real address, DNS). Never
// shipped in termoak-netd.
package wgtest

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/TermoakSSH/server/netd/internal/wg"
)

// Site is a WireGuard peer listening on UDP (all addresses, Port) with the
// address Addr inside its tunnel.
type Site struct {
	Private wg.Key
	Public  wg.Key
	Addr    netip.Addr
	Port    int
	Net     *netstack.Net
	dev     *device.Device
	log     *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
	closers   []io.Closer
}

// SiteConfig describes a site.
type SiteConfig struct {
	// Addr inside the tunnel (10.9.0.1).
	Addr string
	// ListenPort for WireGuard (0: any free port).
	ListenPort int
	// Peer is the client (termoak-netd's node): its public key and its
	// tunnel address (allowed IPs on this side).
	PeerPublic  wg.Key
	PeerAllowed []string
	// NoPeer: start without a client (add them with SetPeer).
	NoPeer bool
	// Private key of the site (generated if zero).
	Private wg.Key
	Log     *slog.Logger
}

// NewSite starts a site.
func NewSite(cfg SiteConfig) (*Site, error) {
	addr, err := netip.ParseAddr(cfg.Addr)
	if err != nil {
		return nil, err
	}
	priv := cfg.Private
	if priv == (wg.Key{}) {
		if priv, err = wg.GenerateKey(); err != nil {
			return nil, err
		}
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, wg.DefaultMTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(f string, a ...any) { log.Debug("site: " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { log.Warn("site: " + fmt.Sprintf(f, a...)) },
	})
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%x\nlisten_port=%d\n", priv[:], cfg.ListenPort)
	if !cfg.NoPeer {
		fmt.Fprintf(&b, "public_key=%x\n", cfg.PeerPublic[:])
		for _, a := range cfg.PeerAllowed {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	s := &Site{Private: priv, Public: priv.PublicKey(), Addr: addr, Net: tnet, dev: dev, log: log}
	text, err := dev.IpcGet()
	if err != nil {
		dev.Close()
		return nil, err
	}
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			s.Port, _ = strconv.Atoi(v)
		}
	}
	if s.Port == 0 {
		dev.Close()
		return nil, errors.New("the site has no listen port")
	}
	return s, nil
}

// Close stops the site.
func (s *Site) Close() {
	s.mu.Lock()
	for _, l := range s.listeners {
		_ = l.Close()
	}
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.dev.Close()
}

func (s *Site) listen(port int) (net.Listener, error) {
	l, err := s.Net.ListenTCPAddrPort(netip.AddrPortFrom(s.Addr, uint16(port)))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, l)
	s.mu.Unlock()
	return l, nil
}

// Echo serves port: it writes banner, then echoes what it reads.
func (s *Site) Echo(port int, banner string) error {
	l, err := s.listen(port)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if banner != "" {
					_, _ = io.WriteString(c, banner)
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return nil
}

// Forward serves port by connecting each connection to target (a real
// TCP address, e.g. an sshd) through the host's network.
func (s *Site) Forward(port int, target string) error {
	l, err := s.listen(port)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				t, err := net.DialTimeout("tcp", target, 10*time.Second)
				if err != nil {
					s.log.Warn("forward failed", "target", target, "error", err)
					return
				}
				defer t.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(t, c); closeWrite(t); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, t); closeWrite(c); done <- struct{}{} }()
				<-done
				<-done
			}()
		}
	}()
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}

// DNS answers A queries on UDP port 53 of the site from records (name →
// IPv4; names without the final dot). Anything else gets NXDOMAIN.
func (s *Site) DNS(records map[string]string) error {
	pc, err := s.Net.ListenUDPAddrPort(netip.AddrPortFrom(s.Addr, 53))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.closers = append(s.closers, pc)
	s.mu.Unlock()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if answer, err := dnsAnswer(buf[:n], records); err == nil {
				_, _ = pc.WriteTo(answer, from)
			}
		}
	}()
	return nil
}

func dnsAnswer(query []byte, records map[string]string) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	hdr := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired}
	ip, found := records[name]
	if !found {
		hdr.RCode = dnsmessage.RCodeNameError
	}
	resp := dnsmessage.NewBuilder(nil, hdr)
	resp.EnableCompression()
	if err := resp.StartQuestions(); err != nil {
		return nil, err
	}
	if err := resp.Question(q); err != nil {
		return nil, err
	}
	if err := resp.StartAnswers(); err != nil {
		return nil, err
	}
	if found && q.Type == dnsmessage.TypeA {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("bad record %s", ip)
		}
		if err := resp.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: addr.As4()}); err != nil {
			return nil, err
		}
	}
	return resp.Finish()
}

// Handshakes tells whether the site completed a handshake with its peer.
func (s *Site) Handshakes() bool {
	text, err := s.dev.IpcGet()
	if err != nil {
		return false
	}
	return strings.Contains(text, "last_handshake_time_sec=") && !strings.Contains(text, "last_handshake_time_sec=0\n")
}

// SetPeer adds a client (or replaces its allowed IPs).
func (s *Site) SetPeer(publicKey string, allowed []string) error {
	k, err := wg.ParseKey(publicKey)
	if err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%x\nreplace_allowed_ips=true\n", k[:])
	for _, a := range allowed {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("invalid allowed IP %q", a)
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	return s.dev.IpcSet(b.String())
}

// RemovePeer removes a client.
func (s *Site) RemovePeer(publicKey string) error {
	k, err := wg.ParseKey(publicKey)
	if err != nil {
		return err
	}
	return s.dev.IpcSet(fmt.Sprintf("public_key=%x\nremove=true\n", k[:]))
}
