// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"io"

	"golang.org/x/time/rate"

	"github.com/anacrolix/torrent"
)

// Client wraps an anacrolix/torrent client behind the bt boundary.
type Client struct {
	inner             *torrent.Client
	uploadRateLimit   int64
	downloadRateLimit int64
}

// Options configure a bt Client.
type Options struct {
	DataDir           string
	ListenPort        int
	NoDHT             bool
	DisableTrackers   bool
	NoUpload          bool
	Seed              bool
	UploadRateLimit   int64
	DownloadRateLimit int64
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
	if opts.UploadRateLimit > 0 {
		cfg.UploadRateLimiter = rate.NewLimiter(rate.Limit(opts.UploadRateLimit), 0)
	}
	if opts.DownloadRateLimit > 0 {
		cfg.DownloadRateLimiter = rate.NewLimiter(rate.Limit(opts.DownloadRateLimit), 0)
	}
	inner, err := torrent.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		inner:             inner,
		uploadRateLimit:   opts.UploadRateLimit,
		downloadRateLimit: opts.DownloadRateLimit,
	}, nil
}

// UploadRateLimit reports the configured global upload rate limit in bytes/sec
// (0 means unlimited).
func (c *Client) UploadRateLimit() int64 {
	return c.uploadRateLimit
}

// DownloadRateLimit reports the configured global download rate limit in
// bytes/sec (0 means unlimited).
func (c *Client) DownloadRateLimit() int64 {
	return c.downloadRateLimit
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
