// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// G2UDPHandler is the callback invoked for each successfully decoded
// datagram. remote is the sender's address.
type G2UDPHandler func(remote net.Addr, pkt *G2Packet)

// G2UDP is a stdlib-only UDP transceiver for Gnutella2 packets. It binds
// a UDP port, encodes outgoing packets with EncodeG2Packet, and decodes
// incoming datagrams with DecodeG2Packet before delivering them to Handler.
type G2UDP struct {
	mu sync.Mutex

	// Configurable bind address. Any of these may be set; the first
	// non-empty one wins. Accepts a "host:port" string or a net.Addr.
	Bind          any
	BindAddr      any
	BindAddress   any
	Address       any
	Listen        any
	ListenAddr    any
	ListenAddress any

	// Handler is invoked for each successfully decoded incoming packet.
	Handler    G2UDPHandler
	OnPacket   G2UDPHandler
	OnReceive  G2UDPHandler
	Callback   G2UDPHandler
	RecvHandler G2UDPHandler

	Logf func(format string, args ...any)

	conn   *net.UDPConn
	laddr  net.Addr
	closed bool
	cancel context.CancelFunc
	// stored handler snapshot for receive loop
}

// NewG2UDP creates a transceiver bound to bindAddr. An optional handler
// may be supplied; otherwise set Handler (or OnPacket/Callback) before Run.
func NewG2UDP(bindAddr string, handler ...G2UDPHandler) (*G2UDP, error) {
	u := &G2UDP{Bind: bindAddr}
	if len(handler) > 0 && handler[0] != nil {
		u.Handler = handler[0]
	}
	return u, nil
}

// NewG2UDPTransceiver is an alias for NewG2UDP.
func NewG2UDPTransceiver(bindAddr string, handler ...G2UDPHandler) (*G2UDP, error) {
	return NewG2UDP(bindAddr, handler...)
}

// NewG2Transceiver is an alias for NewG2UDP.
func NewG2Transceiver(bindAddr string, handler ...G2UDPHandler) (*G2UDP, error) {
	return NewG2UDP(bindAddr, handler...)
}

// NewG2UDPServer is an alias for NewG2UDP.
func NewG2UDPServer(bindAddr string, handler ...G2UDPHandler) (*G2UDP, error) {
	return NewG2UDP(bindAddr, handler...)
}

// NewG2UDPFromOptions builds a transceiver from an options struct.
type G2UDPOptions struct {
	Bind          string
	BindAddr      string
	BindAddress   string
	Address       string
	Listen        string
	ListenAddr    string
	ListenAddress string
	Addr          string
	Handler       G2UDPHandler
	OnPacket      G2UDPHandler
	Callback      G2UDPHandler
	Logf          func(format string, args ...any)
}

func NewG2UDPFromOptions(opts G2UDPOptions) (*G2UDP, error) {
	u := &G2UDP{
		Bind:          opts.Bind,
		BindAddr:      opts.BindAddr,
		BindAddress:   opts.BindAddress,
		Address:       opts.Address,
		Listen:        opts.Listen,
		ListenAddr:    opts.ListenAddr,
		ListenAddress: opts.ListenAddress,
		Handler:       opts.Handler,
		OnPacket:      opts.OnPacket,
		Callback:      opts.Callback,
		Logf:          opts.Logf,
	}
	if opts.Addr != "" {
		u.Bind = opts.Addr
	}
	return u, nil
}

func NewG2UDPWithOptions(opts G2UDPOptions) (*G2UDP, error) {
	return NewG2UDPFromOptions(opts)
}

// bindString resolves the configured bind address.
func (u *G2UDP) bindString() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, v := range []any{u.Bind, u.BindAddr, u.BindAddress, u.Address, u.Listen, u.ListenAddr, u.ListenAddress} {
		switch x := v.(type) {
		case string:
			if x != "" {
				return x
			}
		case net.Addr:
			if x != nil {
				return x.String()
			}
		}
	}
	return ""
}

func (u *G2UDP) handler() G2UDPHandler {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, h := range []G2UDPHandler{u.Handler, u.OnPacket, u.OnReceive, u.Callback, u.RecvHandler} {
		if h != nil {
			return h
		}
	}
	return nil
}

func (u *G2UDP) setHandler(h G2UDPHandler) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Handler = h
}

// ensureBound binds the UDP port if not already bound.
func (u *G2UDP) ensureBound() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errors.New("gnutella: G2UDP closed")
	}
	if u.conn != nil {
		return nil
	}
	bind := ""
	for _, v := range []any{u.Bind, u.BindAddr, u.BindAddress, u.Address, u.Listen, u.ListenAddr, u.ListenAddress} {
		switch x := v.(type) {
		case string:
			if x != "" {
				bind = x
				break
			}
		case net.Addr:
			if x != nil {
				bind = x.String()
				break
			}
		}
		if bind != "" {
			break
		}
	}
	if bind == "" {
		bind = "127.0.0.1:0"
	}
	ua, err := net.ResolveUDPAddr("udp", bind)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	u.conn = conn
	u.laddr = conn.LocalAddr()
	return nil
}

// LocalAddr returns the bound address.
func (u *G2UDP) LocalAddr() net.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.laddr
}

// Addr returns the bound address.
func (u *G2UDP) Addr() net.Addr {
	return u.LocalAddr()
}

// AddressString returns the bound address as a string.
func (u *G2UDP) AddressString() string {
	if a := u.Addr(); a != nil {
		return a.String()
	}
	return ""
}

// Send encodes pkt and transmits it to addr.
func (u *G2UDP) Send(ctx context.Context, addr any, pkt *G2Packet) error {
	if err := u.ensureBound(); err != nil {
		return err
	}
	data, err := EncodeG2Packet(pkt)
	if err != nil {
		return err
	}
	ra, err := resolveG2UDPAddr(addr)
	if err != nil {
		return err
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	if conn == nil {
		return errors.New("gnutella: G2UDP not bound")
	}
	// Respect context deadline if any.
	if ctx != nil {
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetWriteDeadline(dl)
		}
	}
	_, err = conn.WriteTo(data, ra)
	return err
}

func resolveG2UDPAddr(v any) (net.Addr, error) {
	switch x := v.(type) {
	case nil:
		return nil, errors.New("gnutella: nil address")
	case string:
		return net.ResolveUDPAddr("udp", x)
	case net.Addr:
		return x, nil
	case *net.UDPAddr:
		return x, nil
	default:
		return nil, fmt.Errorf("gnutella: unsupported address type %T", v)
	}
}

// Run binds (if needed) and runs the receive loop until ctx is cancelled
// or a fatal error occurs.
func (u *G2UDP) Run(ctxs ...context.Context) error {
	ctx := context.Background()
	if len(ctxs) > 0 && ctxs[0] != nil {
		ctx = ctxs[0]
	}
	if err := u.ensureBound(); err != nil {
		return err
	}
	u.mu.Lock()
	if u.cancel != nil {
		u.cancel()
	}
	cctx, cancel := context.WithCancel(ctx)
	u.cancel = cancel
	u.mu.Unlock()
	defer cancel()

	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()

	buf := make([]byte, 65535)
	for {
		if cctx.Err() != nil {
			return nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if cctx.Err() != nil {
				return nil
			}
			// closed
			if u.isClosed() {
				return nil
			}
			return err
		}
		pkt, err := DecodeG2Packet(buf[:n])
		if err != nil {
			// malformed datagram: drop
			continue
		}
		// copy payload safety
		cp := pkt
		h := u.handler()
		if h != nil {
			h(remote, cp)
		}
	}
}

func (u *G2UDP) isClosed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.closed
}

// Start spawns the receive loop in a goroutine and returns immediately.
func (u *G2UDP) Start(ctxs ...context.Context) error {
	ctx := context.Background()
	if len(ctxs) > 0 && ctxs[0] != nil {
		ctx = ctxs[0]
	}
	if err := u.ensureBound(); err != nil {
		return err
	}
	go func() {
		_ = u.Run(ctx)
	}()
	return nil
}

// Serve is an alias for Run.
func (u *G2UDP) Serve(ctxs ...context.Context) error {
	return u.Run(ctxs...)
}

// ListenAndServe is an alias for Run.
func (u *G2UDP) ListenAndServe(ctxs ...context.Context) error {
	return u.Run(ctxs...)
}

// Close stops the transceiver and closes the socket.
func (u *G2UDP) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	if u.cancel != nil {
		u.cancel()
		u.cancel = nil
	}
	if u.conn != nil {
		err := u.conn.Close()
		u.conn = nil
		return err
	}
	return nil
}

// Shutdown stops the transceiver, honouring ctx.
func (u *G2UDP) Shutdown(ctxs ...context.Context) error {
	return u.Close()
}

// Stop is an alias for Close.
func (u *G2UDP) Stop() error {
	return u.Close()
}
