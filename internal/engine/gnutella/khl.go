// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Gnutella2 host-cache bootstrap over UDP, the "ukhl:" exchange. A G2
// client may ask a hub for its host cache with a one-packet KHLR
// request; the hub answers with a KHLA packet naming the hosts it
// knows. Both travel in SGP datagrams, G2's UDP framing: a fixed header
// carrying a sequence number, a part number and a part count, so a
// packet larger than one datagram can be split and reassembled, then a
// whole G2 packet.
//
// This client sends one KHLR per configured ukhl: endpoint at startup,
// reads the answers for a bounded window, and hands every host it finds
// to the same dial machinery the peer list and the webcaches feed. It
// is deliberately one-shot and best-effort: a hub that never answers
// costs nothing but the window, and the engine is already serving while
// it runs. Serving KHLR, publishing our own host list, and acting on
// unsolicited KHL are out of scope.

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	// khlTimeout bounds the whole KHL exchange: requests go out once,
	// then the socket reads answers until this deadline. The context is
	// the real cancellation path; this keeps a hub that accepts a
	// datagram and then says nothing from holding the bootstrap
	// goroutine, and with it engine shutdown, past a fixed window.
	khlTimeout = 10 * time.Second

	// sgpHeaderSize is the packed SGP datagram header: a three-byte
	// tag, one flags byte, a two-byte sequence, one part number and one
	// part count.
	sgpHeaderSize = 8

	// sgpTag is the tag Shareaza writes on the wire (SGP_TAG_2). The
	// receiver historically also accepted the older "SGP", so both are
	// recognised on the way in.
	sgpTag = "GND"

	sgpFlagDeflate     = 0x01
	sgpFlagAcknowledge = 0x02

	// maxKHLDatagram caps one received datagram. A UDP payload cannot
	// exceed 64 KiB, and this bounds what is buffered before a
	// datagram is even parsed.
	maxKHLDatagram = 64 << 10

	// maxKHLBody caps a reassembled and decompressed answer. A hub that
	// answers with a highly compressible stream must not turn a few
	// datagrams into an unbounded allocation.
	maxKHLBody = 1 << 20

	// maxKHLHosts caps how many hosts one response contributes, so a
	// hostile hub cannot turn a single answer into thousands of dial
	// loops retrying every dialBackoff.
	maxKHLHosts = 256

	// maxKHLAssemblies caps how many partial multi-part answers are
	// buffered at once, keyed by sender and sequence, so a peer cannot
	// make the assembler grow without bound by sending part 1 of many
	// sequences.
	maxKHLAssemblies = 64
)

// sgpDatagram is one parsed SGP datagram: its header fields and its
// payload fragment.
type sgpDatagram struct {
	flags byte
	seq   uint16
	part  byte
	count byte
	data  []byte
}

// encodeSGP wraps a G2 packet in a single-part SGP datagram. This
// client only ever sends one small KHLR, so no fragmentation and no
// deflate are needed on the way out; a hub that deflates its answer is
// handled on the way in.
func encodeSGP(seq uint16, packet []byte) []byte {
	buf := make([]byte, sgpHeaderSize, sgpHeaderSize+len(packet))
	copy(buf[0:3], sgpTag)
	// buf[3] flags: no deflate, no acknowledge.
	binary.LittleEndian.PutUint16(buf[4:6], seq)
	buf[6] = 1 // part 1 of 1
	buf[7] = 1 // one part in total
	return append(buf, packet...)
}

// parseSGP decodes an SGP header. It reports false for a datagram that
// is too short or does not carry a recognised tag; a data datagram has
// count >= 1 and a part in 1..count, while count == 0 marks an
// acknowledgement, which this client ignores.
func parseSGP(b []byte) (sgpDatagram, bool) {
	if len(b) < sgpHeaderSize {
		return sgpDatagram{}, false
	}
	if tag := string(b[0:3]); tag != "SGP" && tag != sgpTag {
		return sgpDatagram{}, false
	}
	return sgpDatagram{
		flags: b[3],
		seq:   binary.LittleEndian.Uint16(b[4:6]),
		part:  b[6],
		count: b[7],
		data:  b[sgpHeaderSize:],
	}, true
}

// khlAssembly collects the parts of one multi-part answer until it is
// whole.
type khlAssembly struct {
	count byte
	parts [][]byte
	have  int
}

// inflate decompresses a zlib stream: SGP_DEFLATE is the zlib format
// Shareaza's Deflate writes, not raw deflate.
func inflate(b []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, maxKHLBody))
}

// khlLoop asks every ukhl: endpoint for its host cache and feeds the
// hosts they answer with into startDial. It returns once the reply
// window closes or the context ends, whichever comes first.
func (e *Engine) khlLoop(ctx context.Context, targets []string) {
	defer e.wg.Done()
	logf := e.opts.Logf

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		logf("ukhl: open udp socket: %v", err)
		return
	}
	defer conn.Close()

	req := encodeSGP(0, (&g2Packet{Type: g2TypeKHLR}).marshal())
	sent := 0
	for _, t := range targets {
		ua, err := net.ResolveUDPAddr("udp4", t)
		if err != nil {
			logf("ukhl %s: %v", t, err)
			continue
		}
		if _, err := conn.WriteToUDP(req, ua); err != nil {
			logf("ukhl %s: send: %v", t, err)
			continue
		}
		sent++
	}
	if sent == 0 {
		return
	}
	logf("ukhl: asked %d hub(s) for their host cache", sent)

	deadline := time.Now().Add(khlTimeout)
	assemblies := make(map[string]*khlAssembly)
	buf := make([]byte, maxKHLDatagram)
	found := 0
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				logf("ukhl: read: %v", err)
			}
			break
		}
		answer, ok := e.decodeKHLDatagram(from, buf[:n], assemblies)
		if !ok {
			continue
		}
		hosts, err := parseKHLHosts(answer, e.opts.khlAllowLoopback)
		if err != nil {
			logf("ukhl %s: %v", from, err)
			continue
		}
		for _, h := range hosts {
			e.startDial(ctx, h)
		}
		found += len(hosts)
	}
	if found > 0 {
		logf("ukhl: %d host(s) discovered", found)
	}
}

// decodeKHLDatagram parses one datagram, assembling a multi-part answer
// and returning the G2 packet it completes. It reports false for a
// datagram that is malformed, an acknowledgement, a duplicate part, or
// a part of an answer that is not yet whole.
func (e *Engine) decodeKHLDatagram(from net.Addr, b []byte, assemblies map[string]*khlAssembly) (*g2Packet, bool) {
	pkt, ok := parseSGP(b)
	if !ok || pkt.count == 0 || pkt.part < 1 || pkt.part > pkt.count {
		return nil, false
	}
	key := from.String() + "#" + strconv.Itoa(int(pkt.seq))
	a := assemblies[key]
	if a == nil {
		if len(assemblies) >= maxKHLAssemblies {
			return nil, false
		}
		a = &khlAssembly{count: pkt.count, parts: make([][]byte, pkt.count)}
		assemblies[key] = a
	}
	if a.count != pkt.count || a.parts[pkt.part-1] != nil {
		return nil, false
	}
	a.parts[pkt.part-1] = append([]byte(nil), pkt.data...)
	a.have++
	if a.have < int(a.count) {
		return nil, false
	}
	delete(assemblies, key)

	body := bytes.Join(a.parts, nil)
	if pkt.flags&sgpFlagDeflate != 0 {
		plain, err := inflate(body)
		if err != nil {
			e.opts.logf()("ukhl %s: inflate answer: %v", from, err)
			return nil, false
		}
		body = plain
	}
	answer, _, err := decodeG2Packet(body)
	if err != nil {
		e.opts.logf()("ukhl %s: answer: %v", from, err)
		return nil, false
	}
	return answer, true
}

// parseKHLHosts returns the dialable host:port addresses a KHL or KHLA
// packet carries, deduplicated in first-seen order. Hosts that are
// unspecified, loopback (unless allowLoopback) or otherwise undialable
// are dropped through the same filter the webcache uses. A packet that
// is not a compound KHL/KHLA, or a truncated one, is an error rather
// than an empty success, so a caller can tell "no hosts" from "not a
// host list".
func parseKHLHosts(p *g2Packet, allowLoopback bool) ([]string, error) {
	if p.Type != g2TypeKHL && p.Type != g2TypeKHLA {
		return nil, fmt.Errorf("gnutella: g2 %s is not a KHL or KHLA packet", p.Type)
	}
	if !p.Compound {
		return nil, fmt.Errorf("%w: %s is not compound", ErrG2Packet, p.Type)
	}
	var (
		hosts []string
		seen  = make(map[string]bool)
	)
	for _, c := range p.Children {
		if c.Type != g2TypeNH && c.Type != g2TypeCH {
			continue
		}
		addr, ok := khlEntryAddr(c, allowLoopback)
		if !ok || seen[addr] {
			continue
		}
		seen[addr] = true
		hosts = append(hosts, addr)
		if len(hosts) >= maxKHLHosts {
			break
		}
	}
	return hosts, nil
}

// khlEntryAddr extracts the address from one NH or CH entry. An entry
// may be flat, carrying a bare address and port, or compound. A
// compound entry carries the address either in an NA sub-packet or, as
// Shareaza's own KHLA builder writes it, as bare bytes after the
// sub-packets, often behind a zero separator byte. Both are handled;
// anything else is not guessed at.
func khlEntryAddr(c *g2Packet, allowLoopback bool) (string, bool) {
	if !c.Compound {
		return dialableKHLAddr(c.Data, allowLoopback)
	}
	if na := c.child(g2TypeNA); na != nil {
		if a, ok := dialableKHLAddr(na.Data, allowLoopback); ok {
			return a, true
		}
	}
	tail := c.Tail
	if len(tail) > 0 && tail[0] == 0 {
		tail = tail[1:]
	}
	return dialableKHLAddr(tail, allowLoopback)
}

// dialableKHLAddr turns a G2 address field into the host:port form the
// dial loops take, applying the same filter the webcache host lines
// pass through. It is deliberately not fooled by a short buffer: a
// field that is not one of the defined lengths is not an address.
func dialableKHLAddr(b []byte, allowLoopback bool) (string, bool) {
	ip, port, ok := khlAddress(b)
	if !ok {
		return "", false
	}
	return dialableAddr(net.JoinHostPort(ip.String(), strconv.Itoa(port)), allowLoopback)
}

// khlAddress decodes a G2 address field. An IPv4 endpoint is four
// octets then a big-endian port; an IPv6 endpoint is sixteen address
// bytes then the port. The combined forms share the IPv4 prefix, so the
// IPv4 endpoint is returned when both are present.
func khlAddress(b []byte) (net.IP, int, bool) {
	switch len(b) {
	case 6, 10, 24, 28: // IPv4 [ + timestamp ] [ + IPv6 ... ]
		ip := net.IPv4(b[0], b[1], b[2], b[3])
		return ip, int(binary.BigEndian.Uint16(b[4:6])), true
	case 18, 22: // IPv6 [ + timestamp ]
		ip := net.IP(append([]byte(nil), b[0:16]...))
		return ip, int(binary.BigEndian.Uint16(b[16:18])), true
	default:
		return nil, 0, false
	}
}
