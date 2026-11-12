// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"testing"
)

func TestClientRateLimits(t *testing.T) {
	tmp := t.TempDir()
	c, err := New(Options{
		DataDir:         tmp,
		ListenPort:      0,
		NoDHT:           true,
		DisableTrackers: true,
		NoUpload:        true,
		Seed:            false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	if got := c.UploadRateLimit(); got != 0 {
		t.Errorf("default UploadRateLimit = %d, want 0", got)
	}
	if got := c.DownloadRateLimit(); got != 0 {
		t.Errorf("default DownloadRateLimit = %d, want 0", got)
	}

	tmp2 := t.TempDir()
	c2, err := New(Options{
		DataDir:           tmp2,
		ListenPort:        0,
		NoDHT:             true,
		DisableTrackers:   true,
		NoUpload:          true,
		Seed:              false,
		UploadRateLimit:   12345,
		DownloadRateLimit: 67890,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c2.Close()

	if got := c2.UploadRateLimit(); got != 12345 {
		t.Errorf("UploadRateLimit = %d, want 12345", got)
	}
	if got := c2.DownloadRateLimit(); got != 67890 {
		t.Errorf("DownloadRateLimit = %d, want 67890", got)
	}
}
