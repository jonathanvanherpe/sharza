// SPDX-License-Identifier: GPL-3.0-or-later

package bt

// Magnet-URI parsing for the BitTorrent engine. This is the only place in
// Sharza that speaks anacrolix/torrent's magnet vocabulary; everything
// outside internal/engine/bt imports the TorrentSpec returned here.

import (
	"errors"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
)

// ParseMagnet parses a magnet URI into a TorrentSpec, exposing the infohash,
// display name, trackers, webseeds and peer sources carried by the link.
// It validates the URI with metainfo.ParseMagnetV2Uri before constructing
// the spec with torrent.TorrentSpecFromMagnetUri.
func ParseMagnet(uri string) (*torrent.TorrentSpec, error) {
	m, err := metainfo.ParseMagnetV2Uri(uri)
	if err != nil {
		return nil, err
	}
	if !m.InfoHash.Ok && !m.V2InfoHash.Ok {
		return nil, errors.New("magnet URI contains no infohash")
	}
	return torrent.TorrentSpecFromMagnetUri(uri)
}
