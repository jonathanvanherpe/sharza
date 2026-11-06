// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
)

// KHLHost is one dialable host returned by a KHL answer, mirroring
// CacheHost. Seen is the (adjusted) timestamp the answer carried for it,
// and Vendor is the four-character vendor code when the answer included
// one (empty otherwise).
type KHLHost struct {
	Addr   string
	Seen   int64
	Vendor string
}

// NewKHLRequest builds the leaf KHLR packet Shareaza sends to a ukhl:
// endpoint. It carries no payload: the request is just the type code.
func NewKHLRequest() *G2Packet {
	return &G2Packet{Type: "KHLR"}
}

// ParseKHLAnswer extracts hosts from a KHLA answer packet. It walks the
// top-level children: NEIGHBOUR_HUB and CACHED_HUB children become
// hosts, a top-level TIMESTAMP sets the clock adjustment applied to each
// host's Seen, and YOURIP is recognised and ignored.
//
// Both on-wire forms are handled: the compound form, where the hub
// child carries nested NODE_ADDRESS / VENDOR / TIMESTAMP children, and
// the inline form, where the address (and optional trailing timestamp)
// follows the nested children as raw bytes.
func ParseKHLAnswer(pkt *G2Packet) []KHLHost {
	var hosts []KHLHost
	if pkt == nil {
		return hosts
	}

	// Top-level clock adjustment: tAdjust = now - topTimestamp.
	var tAdjust int64
	hasTopTS := false
	var topTS int64
	for _, c := range pkt.Children {
		if c == nil || !isKHLTimestampType(c.Type) || len(c.Payload) < 4 {
			continue
		}
		topTS = int64(khlUint32BE(c.Payload[:4]))
		hasTopTS = true
	}
	if hasTopTS {
		tAdjust = time.Now().Unix() - topTS
	}

	for _, c := range pkt.Children {
		if c == nil {
			continue
		}
		if !isKHLHubType(c.Type) {
			continue
		}

		vendor := ""
		var addr string
		haveAddr := false
		var seen int64
		haveSeen := false

		// Compound form: nested children.
		for _, n := range c.Children {
			if n == nil {
				continue
			}
			switch {
			case isKHLNodeAddressType(n.Type):
				if ip, port, ok := parseKHLNodeAddress(n.Payload); ok {
					if !haveAddr {
						addr = net.JoinHostPort(ip, strconv.Itoa(port))
						haveAddr = true
					}
				}
			case isKHLVendorType(n.Type):
				if v := strings.TrimRight(string(n.Payload), "\x00"); v != "" {
					vendor = v
				} else if len(n.Payload) > 0 {
					vendor = string(n.Payload)
				}
			case isKHLTimestampType(n.Type):
				if len(n.Payload) >= 4 {
					seen = int64(khlUint32BE(n.Payload[:4])) + tAdjust
					haveSeen = true
				}
			}
		}

		// Inline form: trailing raw bytes (IP + port, optional timestamp).
		if ip, port, ts, hasTS, ok := parseKHLInline(c.Payload); ok {
			if !haveAddr {
				addr = net.JoinHostPort(ip, strconv.Itoa(port))
				haveAddr = true
			}
			if !haveSeen && hasTS {
				seen = ts + tAdjust
				haveSeen = true
			}
		}

		if !haveAddr || addr == "" {
			continue
		}
		if !haveSeen {
			seen = 0
		}
		hosts = append(hosts, KHLHost{
			Addr:   addr,
			Seen:   seen,
			Vendor: vendor,
		})
	}

	return hosts
}

// FetchKHLHosts fetches hosts from a ukhl: address using the production
// loopback policy (loopback addresses are dropped).
func FetchKHLHosts(ctx context.Context, addr string) ([]KHLHost, error) {
	return fetchKHLHosts(ctx, addr, false)
}

// fetchKHLHosts is FetchKHLHosts with the loopback policy made explicit,
// so tests can point a peer at a listener on 127.0.0.1.
func fetchKHLHosts(ctx context.Context, addr string, allowLoopback bool) ([]KHLHost, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	data, err := EncodeG2Packet(NewKHLRequest())
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, err := conn.WriteToUDP(data, raddr); err != nil {
		return nil, err
	}

	dl := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = conn.SetReadDeadline(dl)

	var hosts []KHLHost
	seen := make(map[string]struct{})
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		pkt, err := DecodeG2Packet(buf[:n])
		if err != nil {
			continue
		}
		for _, h := range ParseKHLAnswer(pkt) {
			a, ok := dialableAddr(h.Addr, allowLoopback)
			if !ok {
				continue
			}
			h.Addr = a
			if _, dup := seen[h.Addr]; dup {
				continue
			}
			seen[h.Addr] = struct{}{}
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

func parseKHLNodeAddress(b []byte) (string, int, bool) {
	if len(b) < 6 {
		return "", 0, false
	}
	v := binary.LittleEndian.Uint32(b[0:4])
	ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
	port := int(b[4])<<8 | int(b[5])
	if port < 1 || port > 65535 {
		return "", 0, false
	}
	return ip, port, true
}

func parseKHLInline(b []byte) (string, int, int64, bool, bool) {
	if len(b) == 6 {
		ip, port, ok := parseKHLNodeAddress(b)
		if !ok {
			return "", 0, 0, false, false
		}
		return ip, port, 0, false, true
	}
	if len(b) == 10 {
		ip, port, ok := parseKHLNodeAddress(b[:6])
		if !ok {
			return "", 0, 0, false, false
		}
		ts := int64(khlUint32BE(b[6:10]))
		return ip, port, ts, true, true
	}
	return "", 0, 0, false, false
}



func isKHLHubType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "NH" || t == "CH" || t == "NEIGHBOUR_HUB" || t == "CACHED_HUB"
}

func isKHLNodeAddressType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "NA" || t == "NODE_ADDRESS"
}

func isKHLVendorType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "V" || t == "VENDOR"
}

func isKHLTimestampType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "TS" || t == "TIMESTAMP"
}


func khlUint32BE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
