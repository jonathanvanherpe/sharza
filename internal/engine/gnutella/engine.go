// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella engine: one listener for inbound peers, one dial loop
// per configured peer address, and a goroutine per connection. All
// logging goes to a Logf sink that defaults to stderr, which is where
// the supervisor collects worker output.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Dial knobs. dialTimeout bounds a single connect attempt; dialBackoff
// paces retries to a peer we cannot reach or that refuses us.
const (
	dialTimeout = 10 * time.Second
	dialBackoff = 5 * time.Second
)

// Options tunes an Engine. Zero values select sane defaults.
type Options struct {
	// Listen is the address to accept connections on, host:port.
	Listen string

	// Peers lists host:port addresses to dial and keep connected.
	Peers []string

	// KeepAliveInterval is how often a silent connection receives an
	// empty PING. Zero means the default 90 s.
	KeepAliveInterval time.Duration

	// IdleTimeout closes a connection that has not delivered a
	// complete message within this window. Zero means 5 minutes.
	IdleTimeout time.Duration

	// Logf receives log lines. Nil logs to stderr.
	Logf func(format string, args ...any)
}

func (o Options) withDefaults() Options {
	if o.KeepAliveInterval <= 0 {
		o.KeepAliveInterval = 90 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	if o.Logf == nil {
		o.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "sharzad: gnutella: "+format+"\n", args...)
		}
	}
	return o
}

func (o Options) logf() func(format string, args ...any) {
	return o.withDefaults().Logf
}

// Engine accepts and maintains Gnutella 0.6 peer connections.
type Engine struct {
	mu      sync.Mutex
	started bool

	opts  Options
	ln    net.Listener
	laddr net.Addr
	ready chan struct{}
	wg    sync.WaitGroup
}

// New returns an idle engine. Call Run with the desired options.
func New() *Engine {
	return &Engine{ready: make(chan struct{})}
}

// Ready is closed once Run has bound the listener. It never closes if
// Run fails before binding.
func (e *Engine) Ready() <-chan struct{} {
	return e.ready
}

// Addr returns the bound listener address (with the real port, even if
// Listen asked for port 0). Valid after Ready.
func (e *Engine) Addr() net.Addr {
	return e.laddr
}

// Run binds the listener, dials the configured peers, and serves until
// ctx is cancelled. It returns nil on a clean shutdown and an error
// only on a genuine failure, so a supervisor can restart the worker on
// error and treat a nil return as "told to stop".
func (e *Engine) Run(ctx context.Context, opts Options) error {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return errors.New("gnutella: engine already running")
	}
	e.started = true
	e.opts = opts.withDefaults()
	e.mu.Unlock()

	ln, err := net.Listen("tcp", e.opts.Listen)
	if err != nil {
		return fmt.Errorf("gnutella: listen %s: %w", e.opts.Listen, err)
	}
	e.ln = ln
	e.laddr = ln.Addr()
	close(e.ready)
	logf := e.opts.Logf

	logf("listening on %s (%d peer(s) configured)", ln.Addr(), len(e.opts.Peers))
	for _, addr := range e.opts.Peers {
		e.wg.Add(1)
		go e.dialLoop(ctx, addr)
	}

	// Closing the listener is how Accept is unblocked when the context
	// ends; connections themselves are closed by each serveConn.
	stopClose := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stopClose()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("gnutella: accept: %w", err)
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			if err := serveConn(ctx, conn, true, e.opts, e.laddr); err != nil {
				logf("inbound %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}

	// The accept loop above adds the last goroutines; by the time it
	// breaks (listener closed), every handler is counted, so Wait is
	// safe from Add-after-Wait.
	e.wg.Wait()
	logf("stopped")
	return nil
}

// dialLoop keeps one outbound peer connected. It retries forever at
// dialBackoff intervals until the context ends: a peer that is down at
// startup may come up later, and a refusal may become an acceptance
// when the far side frees a slot.
func (e *Engine) dialLoop(ctx context.Context, addr string) {
	defer e.wg.Done()
	logf := e.opts.Logf
	for {
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			logf("dial %s failed: %v (retrying in %s)", addr, err, dialBackoff)
		} else if err := serveConn(ctx, conn, false, e.opts, e.laddr); err != nil && ctx.Err() == nil {
			logf("peer %s: %v", addr, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(dialBackoff):
		}
	}
}
