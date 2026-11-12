// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// KadUDPHandler is the callback invoked for each successfully decoded
// datagram. remote is the sender's address.
type KadUDPHandler func(remote net.Addr, pkt *KadPacket)

// KadUDP is a stdlib-only UDP transceiver for Kad packets. It binds a UDP
// port, encodes outgoing packets with KadPacket.Marshal, and decodes
// incoming datagrams with DecodeKadPacket before delivering them to Handler.
type KadUDP struct {
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
	Handler     KadUDPHandler
	OnPacket    KadUDPHandler
	OnReceive   KadUDPHandler
	Callback    KadUDPHandler
	RecvHandler KadUDPHandler

	Logf func(format string, args ...any)

	conn   *net.UDPConn
	laddr  net.Addr
	closed bool
	cancel context.CancelFunc
}

// Aliases.
type KadUDPTransceiver = KadUDP
type KadTransceiver = KadUDP
type KadUDPServer = KadUDP

// NewKadUDP creates a transceiver bound to bindAddr. An optional handler
// may be supplied; otherwise set Handler (or OnPacket/Callback) before Run.
func NewKadUDP(bindAddr string, handler ...KadUDPHandler) (*KadUDP, error) {
	u := &KadUDP{Bind: bindAddr}
	if len(handler) > 0 && handler[0] != nil {
		u.Handler = handler[0]
	}
	return u, nil
}

// NewKadUDPTransceiver is an alias for NewKadUDP.
func NewKadUDPTransceiver(bindAddr string, handler ...KadUDPHandler) (*KadUDP, error) {
	return NewKadUDP(bindAddr, handler...)
}

// NewKadTransceiver is an alias for NewKadUDP.
func NewKadTransceiver(bindAddr string, handler ...KadUDPHandler) (*KadUDP, error) {
	return NewKadUDP(bindAddr, handler...)
}

// NewKadUDPServer is an alias for NewKadUDP.
func NewKadUDPServer(bindAddr string, handler ...KadUDPHandler) (*KadUDP, error) {
	return NewKadUDP(bindAddr, handler...)
}

// KadUDPOptions builds a transceiver from an options struct.
type KadUDPOptions struct {
	Bind          string
	BindAddr      string
	BindAddress   string
	Address       string
	Listen        string
	ListenAddr    string
	ListenAddress string
	Addr          string
	Handler       KadUDPHandler
	OnPacket      KadUDPHandler
	OnReceive     KadUDPHandler
	Callback      KadUDPHandler
	RecvHandler   KadUDPHandler
	Logf          func(format string, args ...any)
}

func NewKadUDPFromOptions(opts KadUDPOptions) (*KadUDP, error) {
	u := &KadUDP{
		Bind:          opts.Bind,
		BindAddr:      opts.BindAddr,
		BindAddress:   opts.BindAddress,
		Address:       opts.Address,
		Listen:        opts.Listen,
		ListenAddr:    opts.ListenAddr,
		ListenAddress: opts.ListenAddress,
		Handler:       opts.Handler,
		OnPacket:      opts.OnPacket,
		OnReceive:     opts.OnReceive,
		Callback:      opts.Callback,
		RecvHandler:   opts.RecvHandler,
		Logf:          opts.Logf,
	}
	if opts.Addr != "" {
		u.Bind = opts.Addr
	}
	return u, nil
}

func NewKadUDPWithOptions(opts KadUDPOptions) (*KadUDP, error) {
	return NewKadUDPFromOptions(opts)
}

// bindString resolves the configured bind address.
func (u *KadUDP) bindString() string {
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

func (u *KadUDP) handler() KadUDPHandler {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, h := range []KadUDPHandler{u.Handler, u.OnPacket, u.OnReceive, u.Callback, u.RecvHandler} {
		if h != nil {
			return h
		}
	}
	return nil
}

func (u *KadUDP) setHandler(h KadUDPHandler) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Handler = h
}

// ensureBound binds the UDP port if not already bound.
func (u *KadUDP) ensureBound() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errors.New("ed2k: KadUDP closed")
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
func (u *KadUDP) LocalAddr() net.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.laddr
}

// Addr returns the bound address.
func (u *KadUDP) Addr() net.Addr {
	return u.LocalAddr()
}

// AddressString returns the bound address as a string.
func (u *KadUDP) AddressString() string {
	if a := u.Addr(); a != nil {
		return a.String()
	}
	return ""
}

// Send encodes pkt and transmits it to addr.
func (u *KadUDP) Send(ctx context.Context, addr any, pkt *KadPacket) error {
	if err := u.ensureBound(); err != nil {
		return err
	}
	if pkt == nil {
		return errors.New("ed2k: nil KadPacket")
	}
	data := pkt.Marshal()
	ra, err := resolveKadUDPAddr(addr)
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
		return errors.New("ed2k: KadUDP not bound")
	}
	if ctx != nil {
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetWriteDeadline(dl)
		}
	}
	_, err = conn.WriteTo(data, ra)
	return err
}

func resolveKadUDPAddr(v any) (net.Addr, error) {
	switch x := v.(type) {
	case nil:
		return nil, errors.New("ed2k: nil address")
	case string:
		return net.ResolveUDPAddr("udp", x)
	case net.Addr:
		return x, nil
	case *net.UDPAddr:
		return x, nil
	default:
		return nil, fmt.Errorf("ed2k: unsupported address type %T", v)
	}
}

// Run binds (if needed) and runs the receive loop until ctx is cancelled
// or a fatal error occurs.
func (u *KadUDP) Run(ctxs ...context.Context) error {
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
			if u.isClosed() {
				return nil
			}
			return err
		}
		pkt, err := DecodeKadPacket(buf[:n])
		if err != nil {
			// malformed datagram: drop
			continue
		}
		cp := pkt
		h := u.handler()
		if h != nil {
			p := cp
			h(remote, &p)
		}
	}
}

func (u *KadUDP) isClosed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.closed
}

// Start spawns the receive loop in a goroutine and returns immediately.
func (u *KadUDP) Start(ctxs ...context.Context) error {
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
func (u *KadUDP) Serve(ctxs ...context.Context) error {
	return u.Run(ctxs...)
}

// ListenAndServe is an alias for Run.
func (u *KadUDP) ListenAndServe(ctxs ...context.Context) error {
	return u.Run(ctxs...)
}

// Close stops the transceiver and closes the socket.
func (u *KadUDP) Close() error {
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
func (u *KadUDP) Shutdown(ctxs ...context.Context) error {
	return u.Close()
}

// Stop is an alias for Close.
func (u *KadUDP) Stop() error {
	return u.Close()
}
