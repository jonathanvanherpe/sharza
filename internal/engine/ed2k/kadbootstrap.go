// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"time"
)

// KadBootstrap performs a single Kad bootstrap round against the node at addr.
// It creates and starts a KadUDP transceiver on an ephemeral port, sends a
// KadBootstrapReq carrying self as the contacting peer, waits for one
// KadBootstrapRes (honouring ctx and a short internal timeout), decodes it,
// and inserts every returned contact into rt (creating a routing table via
// NewKadRoutingTableWithSelf when rt is nil). It returns the decoded contacts.
func KadBootstrap(ctx context.Context, addr net.Addr, self [16]byte, rt *KadRoutingTable) ([]KadContact, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rt == nil {
		rt = NewKadRoutingTableWithSelf(self)
	}

	resCh := make(chan *KadPacket, 1)
	handler := func(remote net.Addr, pkt *KadPacket) {
		if pkt == nil {
			return
		}
		if pkt.opcode() != KAD_BOOTSTRAP_RES {
			return
		}
		select {
		case resCh <- pkt:
		default:
		}
	}

	u, err := NewKadUDP("", handler)
	if err != nil {
		return nil, err
	}

	waitCtx := ctx
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		waitCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
	} else {
		waitCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	if err := u.Start(waitCtx); err != nil {
		u.Close()
		return nil, err
	}
	defer u.Close()

	contact := KadContact{
		ID:      self,
		GUID:    self,
		Hash:    self,
		Version: 9,
		Ver:     9,
	}
	if la := u.LocalAddr(); la != nil {
		if ua, ok := la.(*net.UDPAddr); ok && ua != nil {
			if ip4 := ua.IP.To4(); ip4 != nil {
				copy(contact.IP[:], ip4)
			}
			contact.UDPPort = uint16(ua.Port)
			contact.UDP = uint16(ua.Port)
			contact.TCPPort = uint16(ua.Port)
			contact.TCP = uint16(ua.Port)
			contact.Port = uint16(ua.Port)
		}
	}

	req := KadBootstrapReq{Peer: contact, Sender: contact, Self: contact, From: contact, Local: contact}
	pkt := &KadPacket{Protocol: ProtocolKad, Opcode: KAD_BOOTSTRAP_REQ, Payload: req.Marshal()}
	if err := u.Send(ctx, addr, pkt); err != nil {
		return nil, err
	}

	select {
	case rpkt := <-resCh:
		res, err := DecodeKadBootstrapRes(rpkt.payload())
		if err != nil {
			return nil, err
		}
		contacts := res.contacts()
		for _, c := range contacts {
			rt.Insert(c)
		}
		out := make([]KadContact, len(contacts))
		copy(out, contacts)
		return out, nil
	case <-waitCtx.Done():
		return nil, waitCtx.Err()
	}
}
