// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice wires the existing DialDownload client and the PartMet/PartVerify
// helpers together: a completed transfer is checked against a caller-supplied
// PartMet (byte count, per-part MD4, file hash), returning the indices of any
// corrupt parts. No new opcodes or wire-format changes.
package ed2k

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
)

// partMetIsEmpty reports whether a PartMet carries no usable data.
func partMetIsEmpty(pm PartMet) bool {
	size, _, partSize, parts, _ := pm.normalized()
	return size == 0 && partSize == 0 && len(parts) == 0
}

// downloadedBytes extracts the bytes that landed in dst after a download,
// honouring the reported byte count n so trailing buffer capacity is ignored.
func downloadedBytes(dst any, n int) []byte {
	switch v := dst.(type) {
	case []byte:
		if n >= 0 && n <= len(v) {
			out := make([]byte, n)
			copy(out, v[:n])
			return out
		}
		return append([]byte(nil), v...)
	case *[]byte:
		if v != nil {
			b := *v
			if n >= 0 && n <= len(b) {
				out := make([]byte, n)
				copy(out, b[:n])
				return out
			}
			return append([]byte(nil), b...)
		}
	case bytes.Buffer:
		return append([]byte(nil), v.Bytes()...)
	case *bytes.Buffer:
		if v != nil {
			return append([]byte(nil), v.Bytes()...)
		}
	}
	if w, ok := dst.(interface{ Bytes() []byte }); ok {
		b := w.Bytes()
		if n >= 0 && n <= len(b) {
			out := make([]byte, n)
			copy(out, b[:n])
			return out
		}
		return append([]byte(nil), b...)
	}
	return nil
}

// DialDownloadVerified runs DialDownload, then verifies the downloaded bytes
// against pm using PartMetVerify (and PartVerify), returning the corrupt-part
// indices.
func (e *Engine) DialDownloadVerified(ctx context.Context, target any, hash [16]byte, pm PartMet, dst any) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	pi, ans, qr, n, err := e.DialDownload(ctx, target, hash, dst)
	if err != nil {
		return pi, ans, qr, n, nil, err
	}

	data := downloadedBytes(dst, n)
	ok, corrupt := PartMetVerify(data, pm)
	// Also run the richer PartVerify helper for completeness; its result is
	// not the returned corrupt set (PartMetVerify is authoritative here).
	_, _ = PartVerify(pm, data)
	_ = ok

	return pi, ans, qr, n, corrupt, nil
}

// Aliases on Engine.
func (e *Engine) DownloadVerified(ctx context.Context, target any, hash [16]byte, pm PartMet, dst any) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	return e.DialDownloadVerified(ctx, target, hash, pm, dst)
}

func (e *Engine) DialDownloadVerifiedConn(ctx context.Context, conn net.Conn, hash [16]byte, pm PartMet, dst any, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	// args ignored; conn is the target
	_ = args
	return e.DialDownloadVerified(ctx, conn, hash, pm, dst)
}

// Package-level helper.
func DialDownloadVerified(ctx context.Context, target any, hash [16]byte, pm PartMet, dst any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	eng := New()
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	}
	return eng.DialDownloadVerified(ctx, target, hash, pm, dst)
}

func DownloadVerified(ctx context.Context, target any, hash [16]byte, pm PartMet, dst any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	return DialDownloadVerified(ctx, target, hash, pm, dst, e...)
}

// Package-level conn helper mirroring dialDownload.
func dialDownloadVerified(ctx context.Context, conn net.Conn, hash [16]byte, pm PartMet, dst any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	eng := New()
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	}
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, nil, fmt.Errorf("ed2k: nil connection")
	}
	return eng.DialDownloadVerified(ctx, conn, hash, pm, dst)
}

// DialDownloadVerifiedConn package-level.
func DialDownloadVerifiedConn(ctx context.Context, conn net.Conn, hash [16]byte, pm PartMet, dst any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	return dialDownloadVerified(ctx, conn, hash, pm, dst, e...)
}

// Keep io import used.
var _ = io.EOF
var _ = net.Dial
var _ = context.Background
var _ = fmt.Errorf
var _ = bytes.Buffer{}
