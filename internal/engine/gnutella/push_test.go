// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
	"time"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		ServentID: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		FileIndex: 12345,
		IP:        [4]byte{192, 168, 1, 5},
		Port:      6346,
	}
	enc := EncodePush(p)
	if len(enc) != pushPayloadSize {
		t.Fatalf("expected %d bytes, got %d", pushPayloadSize, len(enc))
	}
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec != p {
		t.Errorf("mismatch: %+v vs %+v", dec, p)
	}
}

func TestDecodePushMalformed(t *testing.T) {
	if _, err := DecodePush(nil); err == nil {
		t.Error("expected error for nil")
	}
	if _, err := DecodePush(make([]byte, 10)); err == nil {
		t.Error("expected error for short")
	}
	if _, err := DecodePush(make([]byte, 30)); err == nil {
		t.Error("expected error for long")
	}
}

func TestPushRegistryRouteLookup(t *testing.T) {
	r := newPushRegistry(100 * time.Millisecond)
	var id [16]byte
	id[0] = 1
	var pc *peerConn
	if _, ok := r.getRoute(id); ok {
		t.Error("expected no route")
	}
	r.setRoute(id, pc)
	if _, ok := r.getRoute(id); ok {
		t.Error("expected no route after setting nil")
	}
}

func TestPushRegistryDialBackClaim(t *testing.T) {
	r := newPushRegistry(100 * time.Millisecond)
	var id [16]byte
	id[1] = 2
	fidx := uint32(5)
	pb, cancel := r.waitFor(id, fidx)
	defer cancel()
	if pb == nil {
		t.Fatal("nil pb")
	}
	done := make(chan struct{})
	var gotConn net.Conn
	go func() {
		c, err := pb.wait()
		if err == nil {
			gotConn = c
		}
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cli, _ := net.Pipe()
	r.claim(id, fidx, cli)
	<-done
	if gotConn != cli {
		t.Error("expected claimed conn")
	}
}

func TestPushRegistryClaimTimeout(t *testing.T) {
	r := newPushRegistry(10 * time.Millisecond)
	var id [16]byte
	pb, cancel := r.waitFor(id, 1)
	defer cancel()
	_, err := pb.wait()
	if err == nil {
		t.Error("expected timeout")
	}
}

func TestPushRegistryNoPendingWrongIndex(t *testing.T) {
	r := newPushRegistry(100 * time.Millisecond)
	var id [16]byte
	pb, cancel := r.waitFor(id, 1)
	defer cancel()
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	r.claim(id, 2, cli)
	_, err := pb.wait()
	if err == nil {
		t.Error("expected timeout - wrong index not claimed")
	}
}

type dummyConn struct{}

func (d *dummyConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (d *dummyConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (d *dummyConn) Close() error                        { return nil }
func (d *dummyConn) LocalAddr() net.Addr                 { return nil }
func (d *dummyConn) RemoteAddr() net.Addr                { return nil }
func (d *dummyConn) SetDeadline(t time.Time) error       { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error   { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error  { return nil }

func TestPushRegistryClaimAny(t *testing.T) {
	r := newPushRegistry(100 * time.Millisecond)
	var id [16]byte
	pb, cancel := r.waitFor(id, 3)
	defer cancel()
	if !r.claimAny(&dummyConn{}) {
		t.Error("expected claimAny to succeed")
	}
	c, err := pb.wait()
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Error("expected conn")
	}
}
