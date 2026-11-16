// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func TestQueueRequestRoundTrip(t *testing.T) {
	h := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	r := QueueRequest{Hash: h}
	b := r.Marshal()
	if len(b) != 16 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeQueueRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Hash != h || g.FileHash != h || g.MD4 != h {
		t.Fatalf("hash mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip mismatch")
	}
	for _, rr := range []QueueRequest{{FileHash: h}, {MD4: h}} {
		if !bytes.Equal(rr.Marshal(), b) {
			t.Fatal("alias mismatch")
		}
	}
	if _, err := DecodeQueueRequest([]byte{1, 2}); err == nil {
		t.Fatal("expected truncated")
	}
	if _, err := DecodeQueueRequest(make([]byte, 17)); err == nil {
		t.Fatal("expected trailing")
	}
}

func TestQueueRequestAliases(t *testing.T) {
	h := [16]byte{9}
	b := QueueRequest{Hash: h}.Marshal()
	if !bytes.Equal(QueueRequest{FileHash: h}.Marshal(), b) {
		t.Fatal("FileHash alias")
	}
	if !bytes.Equal(QueueRequest{MD4: h}.Marshal(), b) {
		t.Fatal("MD4 alias")
	}
}

func TestStartUploadRoundTrip(t *testing.T) {
	b := StartUpload{}.Marshal()
	if len(b) != 0 {
		t.Fatal("start upload payload not empty")
	}
	if _, err := DecodeStartUpload(b); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStartUpload([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
}

func TestQueueReleaseRoundTrip(t *testing.T) {
	b := QueueRelease{}.Marshal()
	if len(b) != 0 {
		t.Fatal("queue release payload not empty")
	}
	if _, err := DecodeQueueRelease(b); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeQueueRelease([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
}

func TestFinishUploadRoundTrip(t *testing.T) {
	b := FinishUpload{}.Marshal()
	if len(b) != 0 {
		t.Fatal("finish upload payload not empty")
	}
	if _, err := DecodeFinishUpload(b); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFinishUpload([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
}

func TestQueueRankRoundTrip(t *testing.T) {
	v := uint32(42)
	q := QueueRank{Rank: v}
	b := q.Marshal()
	if len(b) != 4 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeQueueRank(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Rank != v || g.Slot != v {
		t.Fatalf("rank mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip mismatch")
	}
	for _, alias := range []QueueRank{
		{Slot: v}, {Position: v}, {Index: v}, {Value: v},
		{Number: v}, {Wert: v}, {SlotIndex: v}, {RankIndex: v},
	} {
		if !bytes.Equal(alias.Marshal(), b) {
			t.Fatal("alias mismatch")
		}
	}
	if _, err := DecodeQueueRank([]byte{1, 2}); err == nil {
		t.Fatal("expected truncated")
	}
	if _, err := DecodeQueueRank(make([]byte, 5)); err == nil {
		t.Fatal("expected trailing")
	}
}

func TestQueueRankZero(t *testing.T) {
	b := QueueRank{}.Marshal()
	if len(b) != 4 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeQueueRank(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Rank != 0 {
		t.Fatalf("rank=%d", g.Rank)
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip")
	}
}

func TestOpcodeConstantsQueue(t *testing.T) {
	if OP_QUEUEREQUEST != 0x54 {
		t.Fatal("OP_QUEUEREQUEST")
	}
	if OP_STARTUPLOAD != 0x55 {
		t.Fatal("OP_STARTUPLOAD")
	}
	if OP_QUEUERELEASE != 0x56 {
		t.Fatal("OP_QUEUERELEASE")
	}
	if OP_FINISHUPLOAD != 0x57 {
		t.Fatal("OP_FINISHUPLOAD")
	}
	if OP_QUEUERANK != 0x5C {
		t.Fatal("OP_QUEUERANK")
	}
}

func FuzzQueueRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add(QueueRequest{Hash: [16]byte{1}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		qr, err := DecodeQueueRequest(data)
		if err != nil {
			return
		}
		b := qr.Marshal()
		g, err := DecodeQueueRequest(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzStartUpload(f *testing.F) {
	f.Add([]byte{})
	f.Add(StartUpload{}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		su, err := DecodeStartUpload(data)
		if err != nil {
			return
		}
		b := su.Marshal()
		g, err := DecodeStartUpload(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzQueueRelease(f *testing.F) {
	f.Add([]byte{})
	f.Add(QueueRelease{}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		qr, err := DecodeQueueRelease(data)
		if err != nil {
			return
		}
		b := qr.Marshal()
		g, err := DecodeQueueRelease(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzFinishUpload(f *testing.F) {
	f.Add([]byte{})
	f.Add(FinishUpload{}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		fu, err := DecodeFinishUpload(data)
		if err != nil {
			return
		}
		b := fu.Marshal()
		g, err := DecodeFinishUpload(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzQueueRank(f *testing.F) {
	f.Add([]byte{})
	f.Add(QueueRank{Rank: 1}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		qr, err := DecodeQueueRank(data)
		if err != nil {
			return
		}
		b := qr.Marshal()
		g, err := DecodeQueueRank(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}
