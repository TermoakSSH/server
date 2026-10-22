package netd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TermoakSSH/server/netd/internal/proto"
)

// Version of termoak-netd (set at build time with -ldflags).
var Version = "dev"

// requestTimeout is how long a client has to send its request line.
const requestTimeout = 30 * time.Second

// Access decides which local users may use the socket (checked with
// SO_PEERCRED on every connection, on top of the socket file's mode).
type Access struct {
	// UIDs allowed besides netd's own user and root.
	UIDs map[uint32]bool
	// GID: members of this group are allowed (primary or supplementary
	// group of the peer process); -1 for none.
	GID int
}

// Allowed tells whether a peer may use netd.
func (a Access) Allowed(uid, gid uint32, pid int32) bool {
	if uid == 0 || uid == uint32(os.Getuid()) || a.UIDs[uid] {
		return true
	}
	if a.GID < 0 {
		return false
	}
	if gid == uint32(a.GID) {
		return true
	}
	return inGroup(pid, uint32(a.GID))
}

// inGroup reads the supplementary groups of a process.
func inGroup(pid int32, gid uint32) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Groups:"); ok {
			for _, f := range strings.Fields(rest) {
				if g, err := strconv.ParseUint(f, 10, 32); err == nil && uint32(g) == gid {
					return true
				}
			}
		}
	}
	return false
}

// Server answers the protocol on a listener.
type Server struct {
	M      *Manager
	Log    *slog.Logger
	Access Access
	// Linger after one side of a connection ended (default 30 s).
	Linger time.Duration

	conns sync.WaitGroup
	// Totals for the logs.
	requests atomic.Uint64
	rejected atomic.Uint64
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ln *net.UnixListener) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.Log.Warn("accept failed", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if !s.peerAllowed(c) {
			s.rejected.Add(1)
			_ = c.Close()
			continue
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			s.Handle(c)
		}()
	}
}

func (s *Server) peerAllowed(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil {
		s.Log.Warn("could not read the peer of a connection", "error", errors.Join(err, credErr))
		return false
	}
	if !s.Access.Allowed(cred.Uid, cred.Gid, cred.Pid) {
		s.Log.Warn("rejected a connection from another user", "uid", cred.Uid, "pid", cred.Pid)
		return false
	}
	return true
}

// readLine reads one request line (at most proto.MaxLine bytes) from r,
// leaving whatever follows in r.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > proto.MaxLine {
			return nil, proto.Errorf(proto.CodeInvalid, "the request is longer than %d bytes", proto.MaxLine)
		}
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func writeLine(c net.Conn, v any) error {
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := json.NewEncoder(c).Encode(v)
	_ = c.SetWriteDeadline(time.Time{})
	return err
}

// Handle serves one connection: one request, one answer (and the stream
// after a dial).
func (s *Server) Handle(c net.Conn) {
	defer c.Close()
	s.requests.Add(1)
	_ = c.SetReadDeadline(time.Now().Add(requestTimeout))
	r := bufio.NewReaderSize(c, 64*1024)
	line, err := readLine(r)
	if err != nil {
		var pe *proto.Error
		if errors.As(err, &pe) {
			_ = writeLine(c, proto.ErrorLine(pe))
		}
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req proto.Request
	dec := json.NewDecoder(bytes.NewReader(line))
	if err := dec.Decode(&req); err != nil {
		_ = writeLine(c, proto.ErrorLine(proto.Errorf(proto.CodeInvalid, "the request is not valid JSON: %s", err)))
		return
	}
	if req.V != proto.Version {
		_ = writeLine(c, proto.ErrorLine(proto.Errorf(proto.CodeInvalid, "unsupported protocol version %d (this termoak-netd speaks %d)", req.V, proto.Version)))
		return
	}
	ctx := context.Background()
	answer, err := s.dispatch(ctx, &req, c, r)
	if err != nil {
		var pe *proto.Error
		if !errors.As(err, &pe) {
			pe = proto.Errorf(proto.CodeNetworkError, "%s", err)
		}
		_ = writeLine(c, proto.ErrorLine(pe))
		return
	}
	if answer != nil {
		_ = writeLine(c, answer)
	}
}

func ok(fields map[string]any) map[string]any {
	out := map[string]any{"ok": true}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// dispatch runs a request. A nil answer means it already answered (dial).
func (s *Server) dispatch(ctx context.Context, req *proto.Request, c net.Conn, r *bufio.Reader) (map[string]any, error) {
	switch req.Op {
	case "hello":
		return ok(map[string]any{"v": proto.Version, "version": Version, "kinds": Kinds()}), nil
	case "up":
		st, err := s.M.Up(ctx, req.Network)
		if err != nil {
			return nil, err
		}
		return ok(map[string]any{"status": st}), nil
	case "down":
		if !proto.ValidID(req.NetworkID) {
			return nil, proto.Errorf(proto.CodeInvalid, "invalid network_id")
		}
		s.M.Down(req.NetworkID, "requested")
		return ok(nil), nil
	case "status":
		if !proto.ValidID(req.NetworkID) {
			return nil, proto.Errorf(proto.CodeInvalid, "invalid network_id")
		}
		return ok(map[string]any{"status": s.M.Status(req.NetworkID)}), nil
	case "list":
		return ok(map[string]any{"networks": s.M.List()}), nil
	case "peers":
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		peers, err := s.M.Peers(ctx, req.Network)
		if err != nil {
			return nil, err
		}
		if peers == nil {
			peers = []proto.Peer{}
		}
		return ok(map[string]any{"peers": peers}), nil
	case "dial":
		return nil, s.dial(ctx, req, c, r)
	case "":
		return nil, proto.Errorf(proto.CodeInvalid, "the request has no op")
	default:
		return nil, proto.Errorf(proto.CodeInvalid, "unknown op %q", req.Op)
	}
}

func (s *Server) dial(ctx context.Context, req *proto.Request, c net.Conn, r *bufio.Reader) error {
	timeout := s.M.DialTimeout(req.TimeoutMs)
	dctx, cancel := context.WithTimeout(ctx, timeout)
	stream, err := s.M.Dial(dctx, req.Network, req.Host, req.Port)
	cancel()
	if err != nil {
		return err
	}
	defer stream.Done()
	defer stream.Close()
	remote := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	if err := writeLine(c, ok(map[string]any{"remote": remote})); err != nil {
		return nil
	}
	started := time.Now()
	up, down := pipe(c, r, stream.Conn, s.Linger)
	stream.Log().Info("connection closed", "host", req.Host, "port", req.Port,
		"bytes_up", up, "bytes_down", down, "duration_ms", time.Since(started).Milliseconds())
	return nil
}

type closeWriter interface{ CloseWrite() error }

// defaultLinger: after one side of a connection ends, how long the other
// may stay silent before the connection is closed (a peer that vanished
// never sends FIN through the tunnel).
const defaultLinger = 30 * time.Second

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}

// pipe copies bytes both ways (client → remote from r, which may hold
// buffered bytes) with half-close, until both directions end. An error on
// either side (the network went down...) closes both. Once one side has
// ended, the other is closed after `linger` without bytes.
func pipe(client net.Conn, r *bufio.Reader, remote net.Conn, linger time.Duration) (up, down int64) {
	if linger <= 0 {
		linger = defaultLinger
	}
	var wg sync.WaitGroup
	var upDone atomic.Bool
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		up, err = io.Copy(remote, r)
		closeWrite(remote)
		if err != nil {
			_ = remote.Close()
			_ = client.Close()
			return
		}
		upDone.Store(true)
		_ = remote.SetReadDeadline(time.Now().Add(linger))
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		var err error
		for {
			n, rerr := remote.Read(buf)
			if n > 0 {
				if upDone.Load() {
					_ = remote.SetReadDeadline(time.Now().Add(linger))
				}
				if _, werr := client.Write(buf[:n]); werr != nil {
					err = werr
					break
				}
				down += int64(n)
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					err = rerr
				}
				break
			}
		}
		closeWrite(client)
		if err != nil {
			_ = remote.Close()
			_ = client.Close()
		} else {
			_ = client.SetReadDeadline(time.Now().Add(linger))
		}
	}()
	wg.Wait()
	return up, down
}

// Wait waits for the open connections (shutdown).
func (s *Server) Wait(timeout time.Duration) {
	done := make(chan struct{})
	go func() { s.conns.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// Listen creates the socket: removes a stale one, refuses to replace a live
// one, and sets its mode (and group).
func Listen(path string, mode os.FileMode, gid int) (*net.UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another termoak-netd is listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	// No window with a wider mode: create it with umask 0177 (0600).
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			return nil, fmt.Errorf("could not give %s to group %d: %w", path, gid, err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
