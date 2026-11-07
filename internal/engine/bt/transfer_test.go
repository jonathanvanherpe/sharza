// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
)

const greetingFileContents = "hello,\x00world\n"

func greetingMetaInfo() *metainfo.MetaInfo {
	const data = greetingFileContents
	info := metainfo.Info{
		Name:        "greeting",
		PieceLength: 5,
		Length:      int64(len(data)),
	}
	if err := info.GeneratePieces(func(fi metainfo.FileInfo) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(data)), nil
	}); err != nil {
		panic(err)
	}
	b, err := bencode.Marshal(info)
	if err != nil {
		panic(err)
	}
	mi := &metainfo.MetaInfo{}
	mi.InfoBytes = b
	return mi
}

func TestTorrentDownloadsToCompletion(t *testing.T) {
	seederDataDir := t.TempDir()
	if err := os.WriteFile(seederDataDir+"/greeting", []byte(greetingFileContents), 0o644); err != nil {
		t.Fatal(err)
	}
	mi := greetingMetaInfo()

	seeder, err := New(Options{
		DataDir:         seederDataDir,
		ListenPort:      0,
		NoDHT:           true,
		DisableTrackers: true,
		Seed:            true,
	})
	if err != nil {
		t.Fatalf("seeder New: %v", err)
	}
	defer seeder.Close()

	var buf bytes.Buffer
	if err := mi.Write(&buf); err != nil {
		t.Fatal(err)
	}
	seederTorrent, err := seeder.AddTorrent(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("seeder AddTorrent: %v", err)
	}
	seederTorrent.VerifyData()

	select {
	case <-seederTorrent.Complete().On():
	case <-time.After(30 * time.Second):
		t.Fatal("seeder did not complete")
	}

	leecherDataDir := t.TempDir()
	leecher, err := New(Options{
		DataDir:         leecherDataDir,
		ListenPort:      0,
		NoDHT:           true,
		DisableTrackers: true,
		Seed:            false,
	})
	if err != nil {
		t.Fatalf("leecher New: %v", err)
	}
	defer leecher.Close()

	buf.Reset()
	if err := mi.Write(&buf); err != nil {
		t.Fatal(err)
	}
	leecherTorrent, err := leecher.AddTorrent(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("leecher AddTorrent: %v", err)
	}

	leecherTorrent.DownloadAll()
	leecherTorrent.AddClientPeer(seeder.inner)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	select {
	case <-leecherTorrent.Complete().On():
	case <-ctx.Done():
		t.Fatalf("leecher did not complete: %v", ctx.Err())
	}

	if got := leecherTorrent.BytesCompleted(); got != leecherTorrent.Length() {
		t.Errorf("BytesCompleted=%d, want Length=%d", got, leecherTorrent.Length())
	}
	if err := leecherTorrent.VerifyData(); err != nil {
		t.Errorf("VerifyData: %v", err)
	}
	data, err := os.ReadFile(leecherDataDir + "/greeting")
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if string(data) != greetingFileContents {
		t.Errorf("file contents = %q, want %q", string(data), greetingFileContents)
	}
}