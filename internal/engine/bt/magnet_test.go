// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"testing"
)

const knownMagnet = "magnet:?xt=urn:btih:dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c" +
	"&dn=Example+Name" +
	"&tr=http%3A%2F%2Ftracker.example.com%2Fannounce" +
	"&tr=udp%3A%2F%2Ftracker2.example.com%3A80%2Fannounce" +
	"&ws=http%3A%2F%2Fexample.com%2Fseed" +
	"&x.pe=1.2.3.4%3A5678"

func TestParseMagnetRoundTrip(t *testing.T) {
	spec, err := ParseMagnet(knownMagnet)
	if err != nil {
		t.Fatalf("ParseMagnet: %v", err)
	}
	if spec == nil {
		t.Fatal("nil spec")
	}
	if got := spec.InfoHash.HexString(); got != "dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c" {
		t.Errorf("infohash = %q", got)
	}
	if spec.DisplayName != "Example Name" {
		t.Errorf("display name = %q", spec.DisplayName)
	}
	if len(spec.Trackers) != 1 || len(spec.Trackers[0]) != 2 {
		t.Fatalf("trackers = %#v", spec.Trackers)
	}
	wantTrackers := []string{
		"http://tracker.example.com/announce",
		"udp://tracker2.example.com:80/announce",
	}
	for i, w := range wantTrackers {
		if spec.Trackers[0][i] != w {
			t.Errorf("tracker[%d] = %q, want %q", i, spec.Trackers[0][i], w)
		}
	}
	if len(spec.Webseeds) != 1 || spec.Webseeds[0] != "http://example.com/seed" {
		t.Errorf("webseeds = %#v", spec.Webseeds)
	}
	if len(spec.PeerAddrs) != 1 || spec.PeerAddrs[0] != "1.2.3.4:5678" {
		t.Errorf("peer sources = %#v", spec.PeerAddrs)
	}
}

func TestParseMagnetRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"http://example.com/foo.torrent",
		"magnet:",
		"magnet:?xt=urn:btih:notahex",
		"magnet:?xt=urn:btih:abc",
	}
	for _, c := range cases {
		if _, err := ParseMagnet(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}
