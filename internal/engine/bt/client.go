// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"io"

	"github.com/anacrolix/torrent"
)

// Client wraps an anacrolix/torrent client behind the bt boundary.
type Client struct {
	inner *torrent.Client
}

// Options configure a bt Client.
type Options struct {
	DataDir          string
	ListenPort       int
	NoDHT            bool
	DisableTrackers   bool
	NoUpload         bool
	Seed             bool
}

func (o Options) withDefaults() Options {
	return o
}

// New builds and starts an anacrolix client.
func New(opts Options) (*Client, error) {
	opts = opts.withDefaults()
	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = opts.DataDir
	cfg.ListenPort = opts.ListenPort
	cfg.NoDHT = opts.NoDHT
	cfg.DisableTrackers = opts.DisableTrackers
	cfg.NoUpload = opts.NoUpload
	cfg.Seed = opts.Seed
	cfg.NoDefaultPortForwarding = true
	inner, err := torrent.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner}, nil
}

// AddMagnet validates uri via ParseMagnet and adds it to the client.
func (c *Client) AddMagnet(uri string) (*torrent.Torrent, error) {
	spec, err := ParseMagnet(uri)
	if err != nil {
		return nil, err
	}
	t, _, err := c.inner.AddTorrentSpec(spec)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// AddTorrent decodes a .torrent stream and adds it to the client.
func (c *Client) AddTorrent(r io.Reader) (*torrent.Torrent, error) {
	mi, err := LoadTorrent(r)
	if err != nil {
		return nil, err
	}
	return c.inner.AddTorrent(mi)
}

// Torrents returns all torrents known to the client.
func (c *Client) Torrents() []*torrent.Torrent {
	return c.inner.Torrents()
}

// Close stops the client.
func (c *Client) Close() {
	c.inner.Close()
}