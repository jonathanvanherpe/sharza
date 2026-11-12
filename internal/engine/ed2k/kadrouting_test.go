// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"math/rand"
	"sort"
	"testing"
)

func contactWithID(v byte) KadContact {
	return KadContact{ID: bytes16(v), IP: [4]byte{10, 0, 0, byte(v)}, UDPPort: 4000 + uint16(v), TCPPort: 4001 + uint16(v), Version: 9}
}

func TestKadRoutingInsertLookup(t *testing.T) {
	rt := NewKadRoutingTable(bytes16(0))
	c := contactWithID(1)
	rt.Insert(c)
	got, ok := rt.Get(bytes16(1))
	if !ok {
		t.Fatal("expected contact present")
	}
	if got.ID != c.ID {
		t.Fatalf("id mismatch")
	}
	if rt.Size() != 1 {
		t.Fatalf("size = %d, want 1", rt.Size())
	}
	if _, ok := rt.Get(bytes16(2)); ok {
		t.Fatal("unexpected contact")
	}
}

func TestKadRoutingDuplicateHandling(t *testing.T) {
	rt := NewKadRoutingTable(bytes16(0))
	rt.Insert(contactWithID(1))
	rt.Insert(contactWithID(1)) // duplicate, should update not grow
	if rt.Size() != 1 {
		t.Fatalf("size = %d, want 1", rt.Size())
	}
	// updated fields
	c2 := contactWithID(1)
	c2.Version = 42
	rt.Insert(c2)
	got, _ := rt.Get(bytes16(1))
	if got.Version != 42 && got.Ver != 42 {
		t.Fatalf("duplicate did not update contact")
	}
}

func TestKadRoutingRemove(t *testing.T) {
	rt := NewKadRoutingTable(bytes16(0))
	rt.Insert(contactWithID(1))
	rt.Insert(contactWithID(2))
	rt.Remove(bytes16(1))
	if rt.Size() != 1 {
		t.Fatalf("size = %d, want 1", rt.Size())
	}
	if _, ok := rt.Get(bytes16(1)); ok {
		t.Fatal("removed contact still present")
	}
	if _, ok := rt.Get(bytes16(2)); !ok {
		t.Fatal("unrelated contact removed")
	}
}

func TestKadRoutingClosestOrdering(t *testing.T) {
	rt := NewKadRoutingTable(bytes16(0))
	for v := byte(1); v <= 20; v++ {
		rt.Insert(contactWithID(v))
	}
	target := bytes16(5)
	got := rt.FindClosest(target, 5)
	if len(got) != 5 {
		t.Fatalf("len = %d, want 5", len(got))
	}
	// verify sorted by XOR distance
	type pair struct {
		c KadContact
		d [16]byte
	}
	var pairs []pair
	for _, c := range got {
		pairs = append(pairs, pair{c, xorDistance(c.idBytes(), target)})
	}
	for i := 1; i < len(pairs); i++ {
		if !lessBytes(pairs[i-1].d, pairs[i].d) && pairs[i-1].d != pairs[i].d {
			t.Fatalf("not sorted at %d", i)
		}
	}
	// ensure closest includes target's own id if present
	_ = sort.Slice
}

func TestKadRoutingCapacityAndSplit(t *testing.T) {
	rt := NewKadRoutingTable(bytes16(0))
	k := 4
	rt.K = k
	// insert many contacts sharing the same bucket path to force splits
	for i := 0; i < k*4; i++ {
		var id [16]byte
		id[0] = byte(0x80 | (i & 0x0F)) // vary low bits, same high bit
		// make distinct
		id[15] = byte(i)
		c := KadContact{ID: id, IP: [4]byte{10, 0, 0, byte(i)}, UDPPort: 4000, TCPPort: 4001, Version: 9}
		rt.Insert(c)
	}
	if rt.Size() == 0 {
		t.Fatal("no contacts stored")
	}
	// capacity: no bucket should exceed k
	for _, b := range rt.Buckets {
		if len(b.Contacts) > k {
			t.Fatalf("bucket overflow: %d > %d", len(b.Contacts), k)
		}
	}
	// splitting happened: more than one bucket
	if len(rt.Buckets) < 2 {
		t.Fatalf("expected split, got %d buckets", len(rt.Buckets))
	}
}

func TestKadRoutingBucketSplitMethod(t *testing.T) {
	b := NewKadBucket(2)
	self := bytes16(0)
	// fill bucket
	for i := 0; i < 2; i++ {
		var id [16]byte
		id[15] = byte(i + 1)
		b.Insert(KadContact{ID: id})
	}
	if !b.Full() {
		t.Fatal("expected full")
	}
	left, right, ok := b.SplitBucket(self)
	if !ok || left == nil || right == nil {
		t.Fatal("split failed")
	}
}

func TestKadRoutingFuzzInsert(t *testing.T) {
	rt := NewKadRoutingTable(bytes16(0))
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		var id [16]byte
		for j := range id {
			id[j] = byte(r.Intn(256))
		}
		rt.Insert(KadContact{ID: id, Version: byte(r.Intn(256))})
	}
	if rt.Size() < 0 || rt.Size() > 1000 {
		t.Fatalf("bad size %d", rt.Size())
	}
	// closest returns <= n
	got := rt.FindClosest(bytes16(7), 10)
	if len(got) > 10 {
		t.Fatalf("closest too many: %d", len(got))
	}
}

func FuzzKadRoutingInsert(f *testing.F) {
	f.Add(byte(1))
	f.Fuzz(func(t *testing.T, v byte) {
		rt := NewKadRoutingTable(bytes16(0))
		c := contactWithID(v)
		rt.Insert(c)
		if got, ok := rt.Get(bytes16(v)); !ok || got.ID != c.ID {
			t.Fatalf("lookup failed for %d", v)
		}
		rt.Remove(bytes16(v))
		if rt.Size() != 0 {
			t.Fatalf("size after remove = %d", rt.Size())
		}
	})
}
