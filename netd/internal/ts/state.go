package ts

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The state directory (--state-dir) holds, under tailscale/:
//
//   - <network id>/ for a persistent node (ephemeral: false): tsnet's
//     state (tailscaled.state: the node and machine keys) and termoak.json
//     (the control URL it belongs to). It survives restarts, so the node
//     keeps its name and address; `down` with `forget` (the network was
//     deleted) logs it out and removes it.
//   - eph-<network id>-<random>/ for an ephemeral node: only tsnet's
//     scratch files (its log configuration); the node's state lives in
//     memory and dies with it. Removed when the node stops, and leftovers
//     (a crash) when netd starts.
type stateDir struct {
	root string // <state-dir>/tailscale
}

// stateFile is tsnet's state file name in Dir.
const stateFile = "tailscaled.state"

// markerFile records what a persistent state belongs to.
const markerFile = "termoak.json"

type marker struct {
	ControlURL string `json:"control_url"`
}

func newStateDir(base string) stateDir {
	return stateDir{root: filepath.Join(base, "tailscale")}
}

func (d stateDir) ensure() error {
	return os.MkdirAll(d.root, 0o700)
}

// persistent is the directory of a persistent node.
func (d stateDir) persistent(id string) string {
	return filepath.Join(d.root, id)
}

// scratch makes a new directory for an ephemeral node.
func (d stateDir) scratch(id string) (string, error) {
	if err := d.ensure(); err != nil {
		return "", err
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	dir := filepath.Join(d.root, "eph-"+id+"-"+hex.EncodeToString(b[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// cleanScratch removes the leftovers of ephemeral nodes (netd crashed).
func (d stateDir) cleanScratch() (int, error) {
	list, err := os.ReadDir(d.root)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range list {
		if e.IsDir() && strings.HasPrefix(e.Name(), "eph-") {
			if err := os.RemoveAll(filepath.Join(d.root, e.Name())); err == nil {
				n++
			}
		}
	}
	return n, nil
}

// hasState tells whether a persistent node has its keys on disk.
func hasState(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, stateFile))
	return err == nil && fi.Mode().IsRegular() && fi.Size() > 0
}

func readMarker(dir string) (marker, error) {
	var m marker
	b, err := os.ReadFile(filepath.Join(dir, markerFile))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("invalid %s: %w", markerFile, err)
	}
	return m, nil
}

func writeMarker(dir string, m marker) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, markerFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, markerFile))
}
