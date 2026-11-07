// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"bytes"
	"os"
	"testing"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
)

func TestLoadTorrentFixture(t *testing.T) {
	f, err := os.Open("testdata/flat-url-list.torrent")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mi, err := LoadTorrent(f)
	if err != nil {
		t.Fatalf("LoadTorrent: %v", err)
	}
	if mi == nil {
		t.Fatal("nil metainfo")
	}
	if got := mi.HashInfoBytes().HexString(); got != "9da24e606e4ed9c7b91c1772fb5bf98f82bd9687" {
		t.Errorf("infohash = %q", got)
	}
	info, err := mi.UnmarshalInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.BestName() != "SKODAOCTAVIA336x280" {
		t.Errorf("name = %q", info.BestName())
	}

	spec, err := SpecFromMetaInfo(mi)
	if err != nil {
		t.Fatalf("SpecFromMetaInfo: %v", err)
	}
	if spec == nil {
		t.Fatal("nil spec")
	}
	if spec.InfoHash.HexString() != "9da24e606e4ed9c7b91c1772fb5bf98f82bd9687" {
		t.Errorf("spec infohash = %q", spec.InfoHash.HexString())
	}
	if spec.DisplayName != "SKODAOCTAVIA336x280" {
		t.Errorf("spec name = %q", spec.DisplayName)
	}
	if len(spec.Webseeds) == 0 || spec.Webseeds[0] != "https://archive.org/download/" {
		t.Errorf("webseeds = %#v", spec.Webseeds)
	}
	_ = torrent.TorrentSpec{}
	_ = metainfo.MetaInfo{}
}

func TestLoadTorrentRejectsBadInput(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00, 0x01, 0x02},
		[]byte("not a torrent"),
		// truncated fixture
	}
	data, err := os.ReadFile("testdata/flat-url-list.torrent")
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, data[:len(data)/2])

	for i, c := range cases {
		if _, err := LoadTorrent(bytes.NewReader(c)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestSpecFromMetaInfoPropagatesInfoError(t *testing.T) {
	mi := &metainfo.MetaInfo{}
	_, err := SpecFromMetaInfo(mi)
	if err == nil {
		t.Fatal("expected error for empty metainfo")
	}
}
