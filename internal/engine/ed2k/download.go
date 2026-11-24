// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
)

// downloadChunkSize is the byte range requested in each OP_REQUESTPARTS
// round-trip. Large enough that a small file completes in one round trip;
// the peer clamps the returned range to whatever it actually has.
const downloadChunkSize = 1 << 20

// Downloader moves one file's bytes from a single ed2k peer into a
// caller-supplied destination. Construct with NewDownloader (or the Engine
// convenience) and call Download/Fetch once per transfer. It holds no job
// state: no queue scheduling, no .part.met updates, no AICH wiring.
type Downloader struct {
	// Target is the peer address (string) or an open net.Conn.
	Target any
	// Hash is the file hash in any alias-tolerant form.
	Hash any
	// Dst is the destination: an io.Writer, a []byte buffer, or *[]byte.
	Dst any
	// PartMet, when set, is used by the verified download helpers to check the
	// transferred bytes (byte count, per-part MD4, file hash).
	PartMet PartMet
	// PM is an alias for PartMet.
	PM PartMet
	// Engine supplies identity for the handshake. Nil selects New().
	Engine *Engine
}

// NewDownloader returns a Downloader for one file.
func NewDownloader(target any, hash any, e ...*Engine) *Downloader {
	d := &Downloader{Target: target, Hash: hash}
	if len(e) > 0 && e[0] != nil {
		d.Engine = e[0]
	}
	return d
}

// Download fetches the file into Dst and returns peer identity, file
// availability and the number of bytes written.
func (d *Downloader) Download(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	if len(dst) > 0 && dst[0] != nil {
		d.Dst = dst[0]
	}
	return d.Fetch(ctx)
}

// Fetch is an alias for Download.
func (d *Downloader) Fetch(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	if len(dst) > 0 && dst[0] != nil {
		d.Dst = dst[0]
	}
	eng := d.Engine
	if eng == nil {
		eng = New()
	}
	return eng.DialDownload(ctx, d.Target, d.Hash, d.Dst)
}

// Run is an alias for Download.
func (d *Downloader) Run(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return d.Download(ctx, dst...)
}

// Do is an alias for Download.
func (d *Downloader) Do(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return d.Download(ctx, dst...)
}

// partMet returns the configured PartMet (PartMet or PM alias).
func (d *Downloader) partMet() PartMet {
	pm := d.PartMet
	if partMetIsEmpty(pm) {
		pm = d.PM
	}
	return pm
}

// DownloadVerified fetches the file into Dst and verifies it against d.PartMet,
// returning corrupt indices.
func (d *Downloader) DownloadVerified(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	if len(dst) > 0 && dst[0] != nil {
		d.Dst = dst[0]
	}
	return d.FetchVerified(ctx)
}

// FetchVerified is an alias for DownloadVerified.
func (d *Downloader) FetchVerified(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	if len(dst) > 0 && dst[0] != nil {
		d.Dst = dst[0]
	}
	eng := d.Engine
	if eng == nil {
		eng = New()
	}
	if partMetIsEmpty(d.PartMet) {
		d.PartMet = d.PM
	}
	return eng.DialDownloadVerified(ctx, d.Target, fileRequestHash(d.Hash), d.PartMet, d.Dst)
}

// RunVerified is an alias for DownloadVerified.
func (d *Downloader) RunVerified(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	return d.DownloadVerified(ctx, dst...)
}

// DoVerified is an alias for DownloadVerified.
func (d *Downloader) DoVerified(ctx context.Context, dst ...any) (PeerInfo, FileReqAnswer, QueueResult, int, []int, error) {
	return d.DownloadVerified(ctx, dst...)
}

// dialDownloadConn performs the C2C handshake over an already-open
// connection, sends OP_FILEREQUEST, waits for OP_FILEREQANSWER /
// OP_FILENOTFOUND, then repeatedly builds OP_REQUESTPARTS for the next
// missing byte range, sends it, reads OP_SENDINGPART, and copies Data into
// dst, stopping when the peer reports no more data.
func (e *Engine) dialDownloadConn(ctx context.Context, conn net.Conn, hash [16]byte, dst any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, fmt.Errorf("ed2k: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	// Opt-in protocol obfuscation.
	if _, ok := conn.(*ObfuscatedConn); !ok {
		obfuscated := false
		e.mu.Lock()
		obfuscated = e.opts.Obfuscation || e.opts.Obfuscated
		e.mu.Unlock()
		if obfuscated {
			wrapped, err := ObfuscateConn(conn, nil)
			if err != nil {
				return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, err
			}
			conn = wrapped
		}
	}

	// Handshake first.
	pi, err := e.dialPeerConn(ctx, conn)
	if err != nil {
		return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, err
	}

	// Send OP_FILEREQUEST.
	frFrame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_FILEREQUEST,
		Payload:  FileRequest{Hash: hash}.Marshal(),
	}
	wl := dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return pi, FileReqAnswer{}, QueueResult{}, 0, err
	}
	if _, err := conn.Write(frFrame.Marshal()); err != nil {
		return pi, FileReqAnswer{}, QueueResult{}, 0, err
	}

	// Read until answer / not-found / reject.
	var ans FileReqAnswer
	answerFound := false
	for !answerFound {
		if err := ctx.Err(); err != nil {
			return pi, FileReqAnswer{}, QueueResult{}, 0, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return pi, FileReqAnswer{}, QueueResult{}, 0, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return pi, FileReqAnswer{}, QueueResult{}, 0, err
		}
		op := f.Opcode
		if op == 0 {
			op = f.Type
		}
		if op == 0 {
			op = f.Op
		}
		payload := f.Payload
		if payload == nil {
			payload = f.Data
		}
		if payload == nil {
			payload = f.Body
		}
		if payload == nil {
			payload = []byte{}
		}

		switch op {
		case OP_REJECT:
			return pi, FileReqAnswer{}, QueueResult{}, 0, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILENOTFOUND:
			if _, err := DecodeFileNotFound(payload); err != nil {
				return pi, FileReqAnswer{}, QueueResult{}, 0, err
			}
			return pi, FileReqAnswer{}, QueueResult{}, 0, ErrFileNotFound
		case OP_FILEREQANSWER:
			a, err := DecodeFileReqAnswer(payload)
			if err != nil {
				return pi, FileReqAnswer{}, QueueResult{}, 0, err
			}
			ans = a
			answerFound = true
		default:
			// tolerate leading/unexpected frames
		}
	}

	// Queue round-trip: after OP_FILEREQANSWER, request an upload slot.
	qrFrame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_QUEUEREQUEST,
		Payload:  QueueRequest{Hash: hash}.Marshal(),
	}
	wl = dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return pi, ans, QueueResult{}, 0, err
	}
	if _, err := conn.Write(qrFrame.Marshal()); err != nil {
		return pi, ans, QueueResult{}, 0, err
	}

	var qres QueueResult
	queueDone := false
	for !queueDone {
		if err := ctx.Err(); err != nil {
			return pi, ans, QueueResult{}, 0, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return pi, ans, QueueResult{}, 0, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return pi, ans, QueueResult{}, 0, err
		}
		op := f.Opcode
		if op == 0 {
			op = f.Type
		}
		if op == 0 {
			op = f.Op
		}
		payload := f.Payload
		if payload == nil {
			payload = f.Data
		}
		if payload == nil {
			payload = f.Body
		}
		if payload == nil {
			payload = []byte{}
		}

		switch op {
		case OP_REJECT:
			return pi, ans, QueueResult{}, 0, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILENOTFOUND:
			if _, err := DecodeFileNotFound(payload); err != nil {
				return pi, ans, QueueResult{}, 0, err
			}
			return pi, ans, QueueResult{}, 0, ErrFileNotFound
		case OP_STARTUPLOAD:
			if _, err := DecodeStartUpload(payload); err != nil {
				return pi, ans, QueueResult{}, 0, err
			}
			qres = newQueueGranted()
			queueDone = true
		case OP_QUEUERANK:
			qr, err := DecodeQueueRank(payload)
			if err != nil {
				return pi, ans, QueueResult{}, 0, err
			}
			qres = newQueueRanked(qr.rankValue())
			// Queued: report rank, no transfer.
			return pi, ans, qres, 0, nil
		default:
			// tolerate
		}
	}

	total := 0
	offset := uint32(0)

	for {
		if err := ctx.Err(); err != nil {
			return pi, ans, qres, total, err
		}

		end := offset + downloadChunkSize
		if end < offset {
			end = ^uint32(0)
		}

		rp := RequestParts{
			Hash: hash,
			Von:  [3]uint32{offset, 0, 0},
			Bis:  [3]uint32{end, 0, 0},
		}
		// ensure hash aliases
		rp.FileHash = hash
		rp.MD4 = hash

		rpFrame := Frame{
			Protocol: ProtocolEDonkey,
			Opcode:   OP_REQUESTPARTS,
			Payload:  rp.Marshal(),
		}
		wl = dialDeadline(ctx)
		if err := conn.SetWriteDeadline(wl); err != nil {
			return pi, ans, qres, total, err
		}
		if _, err := conn.Write(rpFrame.Marshal()); err != nil {
			return pi, ans, qres, total, err
		}

		// Read until OP_SENDINGPART / reject / not-found.
		gotPart := false
		for !gotPart {
			if err := ctx.Err(); err != nil {
				return pi, ans, qres, total, err
			}
			rl := dialDeadline(ctx)
			if err := conn.SetReadDeadline(rl); err != nil {
				return pi, ans, qres, total, err
			}
			f, err := readED2KFrame(conn)
			if err != nil {
				if err == io.EOF && total > 0 {
					return pi, ans, qres, total, nil
				}
				return pi, ans, qres, total, err
			}
			op := f.Opcode
			if op == 0 {
				op = f.Type
			}
			if op == 0 {
				op = f.Op
			}
			payload := f.Payload
			if payload == nil {
				payload = f.Data
			}
			if payload == nil {
				payload = f.Body
			}
			if payload == nil {
				payload = []byte{}
			}

			switch op {
			case OP_REJECT:
				return pi, ans, qres, total, fmt.Errorf("ed2k: peer rejected connection")
			case OP_FILENOTFOUND:
				if _, err := DecodeFileNotFound(payload); err != nil {
					return pi, ans, qres, total, err
				}
				return pi, ans, qres, total, ErrFileNotFound
			case OP_SENDINGPART:
				sp, err := DecodeSendingPart(payload)
				if err != nil {
					return pi, ans, qres, total, err
				}
				if sp.hashBytes() == ([16]byte{}) {
					sp.Hash = hash
					sp.FileHash = hash
					sp.MD4 = hash
				}
				data := sp.dataBytes()
				if len(data) > 0 {
					n, werr := writeToDst(dst, data)
					if werr != nil {
						return pi, ans, qres, total, werr
					}
					total += n
				}

				newOffset := sp.bisValue()
				if newOffset == 0 {
					newOffset = offset + uint32(len(data))
				}
				if newOffset <= offset && len(data) > 0 {
					newOffset = offset + uint32(len(data))
				}
				offset = newOffset

				// Stop when peer reports no more data.
				if len(data) == 0 || sp.bisValue() == sp.vonValue() {
					return pi, ans, qres, total, nil
				}
				gotPart = true
			default:
				// tolerate
			}
		}
	}
}

// DialDownload dials a peer (or uses an open connection), performs the
// handshake, file request, and download loop, returning peer identity, file
// availability and the number of bytes written to dst.
func (e *Engine) DialDownload(ctx context.Context, target any, hash any, dst any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}
	// Tolerate callers that pass destination before hash.
	if isDestLike(hash) && isHashLike(dst) {
		hash, dst = dst, hash
	}
	h := fileRequestHash(hash)

	if c, ok := target.(net.Conn); ok {
		return e.dialDownloadConn(ctx, c, h, dst)
	}
	if s, ok := target.(string); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", s, timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, err
		}
		defer conn.Close()
		return e.dialDownloadConn(ctx, conn, h, dst)
	}
	if st, ok := target.(fmt.Stringer); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", st.String(), timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, err
		}
		defer conn.Close()
		return e.dialDownloadConn(ctx, conn, h, dst)
	}
	return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, fmt.Errorf("ed2k: invalid target %T", target)
}

// Aliases.
func (e *Engine) Download(ctx context.Context, target any, hash any, dst any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return e.DialDownload(ctx, target, hash, dst)
}

func (e *Engine) DialDownloadConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownload(ctx, conn, append([]any{e}, args...)...)
}

func (e *Engine) DownloadConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return e.DialDownloadConn(ctx, conn, args...)
}

// Package-level helper (testable), mirroring dialPeer/dialTransfer/dialQueue.
func dialDownload(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var eng *Engine
	var hash any
	var dst any
	for _, a := range args {
		if en, ok := a.(*Engine); ok && en != nil {
			eng = en
			continue
		}
		if b, ok := a.([]byte); ok {
			if hash == nil && len(b) == 16 {
				hash = a
				continue
			}
			if dst == nil {
				dst = a
				continue
			}
		}
		if _, ok := a.(*[]byte); ok {
			if dst == nil {
				dst = a
				continue
			}
		}
		if w, ok := a.(io.Writer); ok {
			if dst == nil {
				dst = w
				continue
			}
		}
		if hash == nil && isHashLike(a) {
			hash = a
			continue
		}
		if dst == nil {
			dst = a
			continue
		}
		if hash == nil {
			hash = a
			continue
		}
	}
	if eng == nil {
		eng = New()
	}
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, fmt.Errorf("ed2k: nil connection")
	}
	h := fileRequestHash(hash)
	return eng.dialDownloadConn(ctx, conn, h, dst)
}

// Package-level dialDownloadConn alias (lowercase).
func dialDownloadConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownload(ctx, conn, args...)
}

// Package-level target helpers.
func DialDownload(ctx context.Context, target any, hash any, dst any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	var eng *Engine
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	} else {
		eng = New()
	}
	return eng.DialDownload(ctx, target, hash, dst)
}

func Download(ctx context.Context, target any, hash any, dst any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return DialDownload(ctx, target, hash, dst, e...)
}

// Conn helpers.
func DialDownloadConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownload(ctx, conn, args...)
}

func DownloadConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownload(ctx, conn, args...)
}

// IO variants.
func dialDownloadIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	if c, ok := rw.(net.Conn); ok {
		return dialDownload(ctx, c, args...)
	}
	return PeerInfo{}, FileReqAnswer{}, QueueResult{}, 0, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func DialDownloadIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownloadIO(ctx, rw, args...)
}

func DownloadIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownloadIO(ctx, rw, args...)
}

// Alias spellings (extra coverage).
func dialDownloadWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownload(ctx, conn, args...)
}

func dialDownloadDirect(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownload(ctx, conn, args...)
}

func (e *Engine) dialDownload(ctx context.Context, target any, hash any, dst any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return e.DialDownload(ctx, target, hash, dst)
}

func (e *Engine) dialDownloadConnMethod(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return e.DialDownloadConn(ctx, conn, args...)
}

func (e *Engine) download(ctx context.Context, target any, hash any, dst any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return e.DialDownload(ctx, target, hash, dst)
}

func download(ctx context.Context, target any, hash any, dst any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	eng := New()
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	}
	return eng.DialDownload(ctx, target, hash, dst)
}

func downloadConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, int, error) {
	return dialDownload(ctx, conn, args...)
}

// Engine.Downloader convenience.
func (e *Engine) Downloader(target any, hash any) *Downloader {
	d := NewDownloader(target, hash)
	d.Engine = e
	if d.Engine == nil {
		d.Engine = e
	}
	return d
}

// Engine.DownloaderVerified convenience.
func (e *Engine) DownloaderVerified(target any, hash any, pm PartMet) *Downloader {
	d := NewDownloader(target, hash)
	d.Engine = e
	d.PartMet = pm
	d.PM = pm
	if d.Engine == nil {
		d.Engine = e
	}
	return d
}

// isDestLike reports whether v looks like a download destination rather
// than a file hash.
func isDestLike(v any) bool {
	if v == nil {
		return false
	}
	if _, ok := v.(io.Writer); ok {
		return true
	}
	if _, ok := v.([]byte); ok {
		return true
	}
	if _, ok := v.(*[]byte); ok {
		return true
	}
	if _, ok := v.(fmt.Stringer); ok {
		// could be either; treat stringer hash? keep false to avoid swap
		return false
	}
	return false
}

// writeToDst writes data to a caller-supplied destination.
func writeToDst(dst any, data []byte) (int, error) {
	if dst == nil {
		return 0, fmt.Errorf("ed2k: nil destination")
	}
	switch v := dst.(type) {
	case io.Writer:
		return v.Write(data)
	case []byte:
		n := copy(v, data)
		if n < len(data) {
			return n, fmt.Errorf("ed2k: destination buffer too small")
		}
		return n, nil
	case *[]byte:
		*v = append(*v, data...)
		return len(data), nil
	default:
		if w, ok := dst.(io.Writer); ok {
			return w.Write(data)
		}
		return 0, fmt.Errorf("ed2k: unsupported destination %T", dst)
	}
}

// Ensure io import usage retained.
var _ = io.EOF
