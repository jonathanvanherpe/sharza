// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"io"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
)

// LoadTorrent decodes a .torrent (metainfo) stream.
func LoadTorrent(r io.Reader) (*metainfo.MetaInfo, error) {
	return metainfo.Load(r)
}

// SpecFromMetaInfo builds a TorrentSpec from decoded metainfo.
func SpecFromMetaInfo(mi *metainfo.MetaInfo) (*torrent.TorrentSpec, error) {
	return torrent.TorrentSpecFromMetaInfoErr(mi)
}
