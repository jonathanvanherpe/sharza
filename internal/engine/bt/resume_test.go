// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anacrolix/torrent"
)

func TestResumeRoundTripPreservesInfohashAndName(t *testing.T) {
	tmp := t.TempDir()
	c, err := New(Options{
		DataDir:         tmp,
		ListenPort:      0,
		NoDHT:           true,
		DisableTrackers: true,
		NoUpload:        true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	f, err := os.Open("testdata/flat-url-list.torrent")
	if err != nil {
		t.Fatal(err)
	}
	tor, err := c.AddTorrent(f)
	f.Close()
	if err != nil {
		t.Fatalf("AddTorrent: %v", err)
	}

	dir := filepath.Join(tmp, "resume")
	if err := c.SaveTorrents(dir); err != nil {
		t.Fatalf("SaveTorrents: %v", err)
	}

	// magnet (no metainfo yet) is skipped; ensure only one file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("saved files = %d, want 1", len(entries))
	}

	c2, err := New(Options{
		DataDir:         t.TempDir(),
		ListenPort:      0,
		NoDHT:           true,
		DisableTrackers: true,
		NoUpload:        true,
	})
	if err != nil {
		t.Fatalf("New2: %v", err)
	}
	defer c2.Close()

	loaded, err := c2.LoadTorrents(dir)
	if err != nil {
		t.Fatalf("LoadTorrents: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded = %d, want 1", len(loaded))
	}
	if got := loaded[0].InfoHash().HexString(); got != tor.InfoHash().HexString() {
		t.Errorf("infohash = %q, want %q", got, tor.InfoHash().HexString())
	}
	if got := loaded[0].Name(); got != tor.Name() {
		t.Errorf("name = %q, want %q", got, tor.Name())
	}
	_ = torrent.TorrentSpec{}
}

func TestResumeMissingDirEmpty(t *testing.T) {
	tmp := t.TempDir()
	c, err := New(Options{DataDir: tmp, ListenPort: 0, NoDHT: true, DisableTrackers: true, NoUpload: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	loaded, err := c.LoadTorrents(filepath.Join(tmp, "does-not-exist"))
	if err != nil {
		t.Fatalf("LoadTorrents missing: %v", err)
	}
	if len(loaded) != 0 {
		t.Errorf("loaded = %d, want 0", len(loaded))
	}
}

func TestResumeSkipsTorrentWithoutMetainfo(t *testing.T) {
	tmp := t.TempDir()
	c, err := New(Options{DataDir: tmp, ListenPort: 0, NoDHT: true, DisableTrackers: true, NoUpload: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	if _, err := c.AddMagnet(knownMagnet); err != nil {
		t.Fatalf("AddMagnet: %v", err)
	}
	// magnet info not available yet
	if c.Torrents()[0].Info() != nil {
		t.Skip("magnet info unexpectedly available")
	}

	dir := filepath.Join(tmp, "resume")
	if err := c.SaveTorrents(dir); err != nil {
		t.Fatalf("SaveTorrents: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected no saved files, got %d", len(entries))
	}
}
