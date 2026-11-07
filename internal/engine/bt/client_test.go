// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"bytes"
	"os"
	"testing"

	"github.com/anacrolix/torrent"
)

func TestClientLifecycle(t *testing.T) {
	tmp := t.TempDir()
	c, err := New(Options{
		DataDir:          tmp,
		ListenPort:       0,
		NoDHT:            true,
		DisableTrackers:  true,
		NoUpload:         true,
		Seed:             false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// Add committed fixture via AddTorrent.
	f, err := os.Open("testdata/flat-url-list.torrent")
	if err != nil {
		t.Fatal(err)
	}
	tor, err := c.AddTorrent(f)
	f.Close()
	if err != nil {
		t.Fatalf("AddTorrent fixture: %v", err)
	}
	if tor == nil {
		t.Fatal("nil torrent from fixture")
	}
	if got := tor.InfoHash().HexString(); got != "9da24e606e4ed9c7b91c1772fb5bf98f82bd9687" {
		t.Errorf("fixture infohash = %q", got)
	}
	if got := tor.Name(); got != "SKODAOCTAVIA336x280" {
		t.Errorf("fixture name = %q", got)
	}

	// Add known magnet.
	magTor, err := c.AddMagnet(knownMagnet)
	if err != nil {
		t.Fatalf("AddMagnet: %v", err)
	}
	if magTor == nil {
		t.Fatal("nil torrent from magnet")
	}
	if got := magTor.InfoHash().HexString(); got != "dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c" {
		t.Errorf("magnet infohash = %q", got)
	}

	if got := len(c.Torrents()); got != 2 {
		t.Errorf("Torrents() len = %d, want 2", got)
	}

	// Invalid inputs must error without adding a torrent.
	before := len(c.Torrents())
	for _, cse := range []string{"", "magnet:", "http://example.com/x.torrent"} {
		if _, err := c.AddMagnet(cse); err == nil {
			t.Errorf("AddMagnet(%q): expected error", cse)
		}
	}
	if _, err := c.AddTorrent(bytes.NewReader([]byte("not a torrent"))); err == nil {
		t.Error("AddTorrent bad input: expected error")
	}
	// truncated fixture
	data, err := os.ReadFile("testdata/flat-url-list.torrent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddTorrent(bytes.NewReader(data[:len(data)/2])); err == nil {
		t.Error("AddTorrent truncated: expected error")
	}
	if got := len(c.Torrents()); got != before {
		t.Errorf("Torrents() len changed after invalid inputs: %d -> %d", before, got)
	}
	_ = torrent.TorrentSpec{}
}
