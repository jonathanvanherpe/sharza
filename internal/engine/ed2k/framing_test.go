// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		proto   byte
		op      byte
		payload []byte
	}{
		{"reject", ProtocolEDonkey, OP_REJECT, nil},
		{"servermsg", ProtocolEDonkey, OP_SERVERMESSAGE, []byte{0x02, 0x00, 'h', 'i'}},
		{"offerfiles", ProtocolEMule, OP_OFFERFILES, []byte{0x00, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Frame{Protocol: c.proto, Opcode: c.op, Payload: c.payload}
			b := f.Marshal()
			g, err := DecodeFrame(b)
			if err != nil {
				t.Fatal(err)
			}
			if g.Protocol != c.proto {
				t.Fatalf("protocol mismatch: %x vs %x", g.Protocol, c.proto)
			}
			if g.Opcode != c.op || g.Type != c.op || g.Op != c.op {
				t.Fatalf("opcode mismatch")
			}
			if !bytes.Equal(g.Payload, c.payload) {
				t.Fatalf("payload mismatch: %x vs %x", g.Payload, c.payload)
			}
			if g.Size != uint32(1+len(c.payload)) {
				t.Fatalf("size mismatch: %d", g.Size)
			}
			if !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("re-encode mismatch")
			}
		})
	}
}

func TestFrameReadFrame(t *testing.T) {
	f := Frame{Protocol: ProtocolEDonkey, Opcode: OP_REJECT, Payload: nil}
	b := f.Marshal()
	g, err := ReadFrame(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if g.Opcode != OP_REJECT {
		t.Fatal("opcode mismatch")
	}
	// trailing data: ReadFrame reads the frame then checks for extra bytes
	_, err = ReadFrame(bytes.NewReader(append(b, 0x00)))
	if err == nil {
		t.Fatal("expected error on trailing data")
	}
}

func TestFrameMalformed(t *testing.T) {
	cases := [][]byte{
		{},                                    // empty
		{0xE3},                                // too short
		{0xE3, 0x00, 0x00, 0x00, 0x00, 0x05}, // size 0
		{0xE3, 0xFF, 0xFF, 0xFF, 0xFF, 0x05}, // huge size
		{0xE3, 0x02, 0x00, 0x00, 0x00, 0x05}, // size 2 but only header (truncated payload)
	}
	for i, c := range cases {
		if _, err := DecodeFrame(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
	// trailing bytes
	b := Frame{Protocol: ProtocolEDonkey, Opcode: OP_REJECT}.Marshal()
	if _, err := DecodeFrame(append(b, 0x00)); err == nil {
		t.Fatal("expected trailing error")
	}
}

func TestOpcodeConstants(t *testing.T) {
	if OP_REJECT != 0x05 {
		t.Fatal("OP_REJECT")
	}
	if OP_SERVERMESSAGE != 0x38 {
		t.Fatal("OP_SERVERMESSAGE")
	}
	if OP_OFFERFILES != 0x15 {
		t.Fatal("OP_OFFERFILES")
	}
}

func TestRejectRoundTrip(t *testing.T) {
	b := Reject{}.Marshal()
	if len(b) != 0 {
		t.Fatal("reject payload not empty")
	}
	if _, err := DecodeReject(b); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReject([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
}

func TestServerMessageRoundTrip(t *testing.T) {
	m := ServerMessage{Message: "hello"}
	b := m.Marshal()
	g, err := DecodeServerMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Message != "hello" {
		t.Fatalf("got %q", g.Message)
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("re-encode mismatch")
	}
	// malformed
	if _, err := DecodeServerMessage([]byte{0x01}); err == nil {
		t.Fatal("expected error short")
	}
	if _, err := DecodeServerMessage([]byte{0x01, 0x00, 'x', 'y'}); err == nil {
		t.Fatal("expected error trailing")
	}
}

func TestOfferFilesRoundTrip(t *testing.T) {
	o := OfferFiles{Files: []OfferedFile{
		{Hash: [16]byte{1, 2, 3}, ID: 42, Port: 4662, Tags: []Tag{{Type: 0x03, Key: 0x01, Value: 7}}},
	}}
	b := o.Marshal()
	g, err := DecodeOfferFiles(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Files) != 1 {
		t.Fatal("file count")
	}
	if g.Files[0].ID != 42 || g.Files[0].Port != 4662 {
		t.Fatal("field mismatch")
	}
	if !bytes.Equal(g.Files[0].Hash[:], o.Files[0].Hash[:]) {
		t.Fatal("hash mismatch")
	}
	if len(g.Files[0].Tags) != 1 || g.Files[0].Tags[0].Value != 7 {
		t.Fatal("tag mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("re-encode mismatch")
	}
	// empty
	o2 := OfferFiles{}
	b2 := o2.Marshal()
	g2, err := DecodeOfferFiles(b2)
	if err != nil {
		t.Fatal(err)
	}
	if len(g2.Files) != 0 {
		t.Fatal("expected 0 files")
	}
}

func TestTagRoundTrip(t *testing.T) {
	tag := Tag{Type: 0x02, Key: 0x01, Str: "abc"}
	b := tag.Marshal()
	g, n, err := DecodeTag(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b) {
		t.Fatalf("consumed %d vs %d", n, len(b))
	}
	if g.Str != "abc" {
		t.Fatalf("got %q", g.Str)
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("re-encode mismatch")
	}
}

func TestFrameAliases(t *testing.T) {
	f := Frame{Protocol: ProtocolEDonkey, Type: OP_REJECT}
	if f.Opcode != 0 {
		// Opcode field not set, but normalized uses Type
	}
	b := f.Marshal()
	g, err := UnmarshalFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Op != OP_REJECT {
		t.Fatal("alias mismatch")
	}
	// method forms
	var f2 Frame
	if err := f2.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if err := f2.Decode(b); err != nil {
		t.Fatal(err)
	}
	var m ServerMessage
	if err := m.Unmarshal(ServerMessage{Message: "x"}.Marshal()); err != nil {
		t.Fatal(err)
	}
	var o OfferFiles
	if err := o.Decode(OfferFiles{}.Marshal()); err != nil {
		t.Fatal(err)
	}
}

func TestReadFrameEOF(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected eof")
	}
	r := bytes.NewReader([]byte{0xE3, 0x01})
	if _, err := ReadFrame(r); err == nil {
		t.Fatal("expected eof")
	}
}

func FuzzEd2kFrame(f *testing.F) {
	f.Add([]byte{0xE3, 0x01, 0x00, 0x00, 0x00, 0x05})
	f.Add([]byte{0xE3, 0x06, 0x00, 0x00, 0x00, 0x38, 0x02, 0x00, 'h', 'i'})
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := DecodeFrame(data)
		if err != nil {
			return
		}
		out := fr.Marshal()
		fr2, err2 := DecodeFrame(out)
		if err2 != nil {
			t.Fatalf("re-decode failed: %v", err2)
		}
		if !bytes.Equal(fr.Marshal(), fr2.Marshal()) {
			t.Fatal("round-trip mismatch")
		}
		// exercise ReadFrame
		_, _ = ReadFrame(bytes.NewReader(out))
	})
}
