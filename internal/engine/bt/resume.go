// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anacrolix/torrent"
)

// SaveTorrents writes the metainfo of every torrent whose info is known to
// <dir>/<infohash>.torrent, creating dir if needed. Torrents whose metainfo
// is not yet available are skipped. It returns the first error encountered.
func (c *Client) SaveTorrents(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("bt: create resume dir %q: %w", dir, err)
	}
	for _, t := range c.Torrents() {
		if t == nil || t.Info() == nil {
			continue
		}
		path := filepath.Join(dir, t.InfoHash().HexString()+".torrent")
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("bt: create %q: %w", path, err)
		}
		mi := t.Metainfo()
		if err := mi.Write(f); err != nil {
			f.Close()
			return fmt.Errorf("bt: write %q: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("bt: close %q: %w", path, err)
		}
	}
	return nil
}

// LoadTorrents reads every *.torrent in dir, decodes it via LoadTorrent and
// SpecFromMetaInfo, and re-adds it through the client. It returns the added
// torrents. A missing directory is treated as empty and yields no error.
// Per-file decode/add errors are reported (the first one encountered) after
// the remaining files have been processed.
func (c *Client) LoadTorrents(dir string) ([]*torrent.Torrent, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*torrent.Torrent{}, nil
		}
		return nil, fmt.Errorf("bt: read resume dir %q: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".torrent") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	added := []*torrent.Torrent{}
	var firstErr error
	for _, name := range names {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("bt: open %q: %w", path, err)
			}
			continue
		}
		mi, err := LoadTorrent(f)
		f.Close()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("bt: decode %q: %w", path, err)
			}
			continue
		}
		spec, err := SpecFromMetaInfo(mi)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("bt: spec %q: %w", path, err)
			}
			continue
		}
		t, _, err := c.inner.AddTorrentSpec(spec)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("bt: add %q: %w", path, err)
			}
			continue
		}
		if t != nil {
			added = append(added, t)
		}
	}
	return added, firstErr
}
