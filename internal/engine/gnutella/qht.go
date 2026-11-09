// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const QHT = "QHT"

const (
	QHTResetType byte = 0
	QHTPatchType byte = 1
)

type QHTReset struct {
	Slots  uint32
	InfVal uint8
}

type QHTPatch struct {
	SeqNo      uint8
	SeqSize    uint8
	Compressed bool
	Bits       uint8
	Data       []byte
}

var (
	ErrQHTBadType   = errors.New("gnutella: malformed QHT packet type")
	ErrQHTTruncated = errors.New("gnutella: truncated QHT payload")
	ErrQHTBadSlots  = errors.New("gnutella: invalid QHT slot count")
	ErrQHTBadBits   = errors.New("gnutella: invalid QHT bit count")
)

func EncodeQHTReset(v any) []byte {
	r, ok := asQHTReset(v)
	if !ok {
		return nil
	}
	out := make([]byte, 6)
	out[0] = QHTResetType
	binary.LittleEndian.PutUint32(out[1:5], r.Slots)
	out[5] = r.InfVal
	return out
}

func DecodeQHTReset(v any) (QHTReset, error) {
	b, err := qhtInputBytes(v)
	if err != nil {
		return QHTReset{}, err
	}
	if len(b) < 6 {
		return QHTReset{}, fmt.Errorf("%w: got %d bytes", ErrQHTTruncated, len(b))
	}
	if len(b) != 6 {
		return QHTReset{}, fmt.Errorf("%w: got %d bytes", ErrQHTTruncated, len(b))
	}
	if b[0] != QHTResetType {
		return QHTReset{}, fmt.Errorf("%w: got type %d", ErrQHTBadType, b[0])
	}
	slots := binary.LittleEndian.Uint32(b[1:5])
	if slots == 0 {
		return QHTReset{}, fmt.Errorf("%w: %d", ErrQHTBadSlots, slots)
	}
	return QHTReset{Slots: slots, InfVal: b[5]}, nil
}

func EncodeQHTPatch(v any) []byte {
	p, ok := asQHTPatch(v)
	if !ok {
		return nil
	}
	out := make([]byte, 5+len(p.Data))
	out[0] = QHTPatchType
	out[1] = p.SeqNo
	out[2] = p.SeqSize
	if p.Compressed {
		out[3] = 1
	}
	out[4] = p.Bits
	copy(out[5:], p.Data)
	return out
}

func DecodeQHTPatch(v any) (QHTPatch, error) {
	b, err := qhtInputBytes(v)
	if err != nil {
		return QHTPatch{}, err
	}
	if len(b) < 5 {
		return QHTPatch{}, fmt.Errorf("%w: got %d bytes", ErrQHTTruncated, len(b))
	}
	if b[0] != QHTPatchType {
		return QHTPatch{}, fmt.Errorf("%w: got type %d", ErrQHTBadType, b[0])
	}
	bits := b[4]
	if bits > 8 {
		return QHTPatch{}, fmt.Errorf("%w: %d", ErrQHTBadBits, bits)
	}
	return QHTPatch{
		SeqNo:      b[1],
		SeqSize:    b[2],
		Compressed: b[3] != 0,
		Bits:       bits,
		Data:       cloneBytes(b[5:]),
	}, nil
}

func EncodeQHT(v any) []byte {
	var payload []byte
	switch x := v.(type) {
	case QHTReset:
		payload = EncodeQHTReset(x)
	case *QHTReset:
		if x != nil {
			payload = EncodeQHTReset(*x)
		}
	case QHTPatch:
		payload = EncodeQHTPatch(x)
	case *QHTPatch:
		if x != nil {
			payload = EncodeQHTPatch(*x)
		}
	case *G2Packet:
		if x != nil && len(x.Payload) > 0 {
			payload = cloneBytes(x.Payload)
		}
	case []byte:
		payload = cloneBytes(x)
	case string:
		payload = []byte(x)
	default:
		return nil
	}
	if payload == nil {
		return nil
	}
	pkt := &G2Packet{Type: QHT, Payload: payload}
	b, err := EncodeG2Packet(pkt)
	if err != nil {
		return nil
	}
	return b
}

func DecodeQHT(v any) (any, error) {
	pkt, payload, err := qhtExtractPacket(v)
	if err != nil {
		return nil, err
	}
	if pkt != nil && pkt.Type != "" && pkt.Type != QHT {
		return nil, fmt.Errorf("%w: got type %q", ErrQHTBadType, pkt.Type)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrQHTTruncated)
	}
	switch payload[0] {
	case QHTResetType:
		r, err := DecodeQHTReset(payload)
		if err != nil {
			return nil, err
		}
		return r, nil
	case QHTPatchType:
		p, err := DecodeQHTPatch(payload)
		if err != nil {
			return nil, err
		}
		return p, nil
	default:
		return nil, fmt.Errorf("%w: got type %d", ErrQHTBadType, payload[0])
	}
}

func EncodeQHTPacket(v any) (*G2Packet, error) {
	var payload []byte
	switch x := v.(type) {
	case QHTReset:
		payload = EncodeQHTReset(x)
	case *QHTReset:
		if x != nil {
			payload = EncodeQHTReset(*x)
		}
	case QHTPatch:
		payload = EncodeQHTPatch(x)
	case *QHTPatch:
		if x != nil {
			payload = EncodeQHTPatch(*x)
		}
	case []byte:
		payload = cloneBytes(x)
	case string:
		payload = []byte(x)
	default:
		return nil, fmt.Errorf("gnutella: unsupported QHT value %T", v)
	}
	if payload == nil {
		return nil, fmt.Errorf("%w: nil payload", ErrQHTTruncated)
	}
	return &G2Packet{Type: QHT, Payload: payload}, nil
}

func DecodeQHTPacket(v any) (*G2Packet, error) {
	pkt, payload, err := qhtExtractPacket(v)
	if err != nil {
		return nil, err
	}
	if pkt != nil && pkt.Type != "" && pkt.Type != QHT {
		return nil, fmt.Errorf("%w: got type %q", ErrQHTBadType, pkt.Type)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrQHTTruncated)
	}
	if payload[0] != QHTResetType && payload[0] != QHTPatchType {
		return nil, fmt.Errorf("%w: got type %d", ErrQHTBadType, payload[0])
	}
	if pkt != nil {
		return pkt, nil
	}
	return &G2Packet{Type: QHT, Payload: payload}, nil
}

func asQHTReset(v any) (QHTReset, bool) {
	switch x := v.(type) {
	case QHTReset:
		return x, true
	case *QHTReset:
		if x != nil {
			return *x, true
		}
	}
	return QHTReset{}, false
}

func asQHTPatch(v any) (QHTPatch, bool) {
	switch x := v.(type) {
	case QHTPatch:
		return x, true
	case *QHTPatch:
		if x != nil {
			return *x, true
		}
	}
	return QHTPatch{}, false
}

func qhtInputBytes(v any) ([]byte, error) {
	switch x := v.(type) {
	case *G2Packet:
		if x == nil {
			return nil, fmt.Errorf("gnutella: nil G2 packet")
		}
		return cloneBytes(x.Payload), nil
	case []byte:
		return cloneBytes(x), nil
	case string:
		return []byte(x), nil
	case io.Reader:
		b, err := io.ReadAll(x)
		if err != nil {
			return nil, err
		}
		return b, nil
	default:
		return nil, fmt.Errorf("gnutella: unsupported QHT input %T", v)
	}
}

func qhtExtractPacket(v any) (*G2Packet, []byte, error) {
	switch x := v.(type) {
	case *G2Packet:
		if x == nil {
			return nil, nil, fmt.Errorf("gnutella: nil G2 packet")
		}
		return x, cloneBytes(x.Payload), nil
	case []byte:
		pkt, err := DecodeG2Packet(x)
		if err != nil {
			return nil, cloneBytes(x), nil
		}
		return pkt, cloneBytes(pkt.Payload), nil
	case string:
		pkt, err := DecodeG2Packet([]byte(x))
		if err != nil {
			return nil, []byte(x), nil
		}
		return pkt, cloneBytes(pkt.Payload), nil
	case io.Reader:
		b, err := io.ReadAll(x)
		if err != nil {
			return nil, nil, err
		}
		pkt, err := DecodeG2Packet(b)
		if err != nil {
			return nil, b, nil
		}
		return pkt, cloneBytes(pkt.Payload), nil
	default:
		return nil, nil, fmt.Errorf("gnutella: unsupported QHT input %T", v)
	}
}
