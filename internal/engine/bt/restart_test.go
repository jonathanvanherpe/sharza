// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestTorrentSurvivesRestart(t *testing.T) {
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

	var buf bytes.Buffer
	if err := mi.Write(&buf); err != nil {
		t.Fatal(err)
	}
	seederTorrent, err := seeder.AddTorrent(bytes.NewReader(buf.Bytes()))
	if err != nil {
		seeder.Close()
		t.Fatalf("seeder AddTorrent: %v", err)
	}
	seederTorrent.VerifyData()

	select {
	case <-seederTorrent.Complete().On():
	case <-time.After(30 * time.Second):
		seeder.Close()
		t.Fatal("seeder did not complete")
	}

	resumeDir := t.TempDir()
	if err := seeder.SaveTorrents(resumeDir); err != nil {
		seeder.Close()
		t.Fatalf("SaveTorrents: %v", err)
	}
	seeder.Close()

	leecher, err := New(Options{
		DataDir:         seederDataDir,
		ListenPort:      0,
		NoDHT:           true,
		DisableTrackers: true,
		NoUpload:        true,
	})
	if err != nil {
		t.Fatalf("leecher New: %v", err)
	}
	defer leecher.Close()

	loaded, err := leecher.LoadTorrents(resumeDir)
	if err != nil {
		t.Fatalf("LoadTorrents: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded = %d, want 1", len(loaded))
	}

	rt := loaded[0]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	select {
	case <-rt.Complete().On():
	case <-ctx.Done():
	}

	if got := rt.BytesCompleted(); got != rt.Length() {
		t.Errorf("BytesCompleted=%d, want Length=%d", got, rt.Length())
	}
	if !rt.Complete().Bool() {
		t.Errorf("Complete() = false, want true")
	}
	if err := rt.VerifyData(); err != nil {
		t.Errorf("VerifyData: %v", err)
	}
}
