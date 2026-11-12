// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
)

type Options struct {
	Servers []string
	Listen  string
	Logf    func(format string, args ...any)
}

func (o Options) withDefaults() Options {
	if o.Logf == nil {
		o.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "sharzad: ed2k: "+format+"\n", args...)
		}
	}
	return o
}

type Engine struct {
	mu      sync.Mutex
	started bool

	opts  Options
	ln    net.Listener
	laddr net.Addr
	ready chan struct{}
	wg    sync.WaitGroup

	clientID      uint32
	lowID         bool
	tcpFlags      uint32
	serverFlags   uint32
	clientIP      [4]byte
	serverList    []ServerEntry
	messages      []string
	rejected      bool
	gotServerList bool
}

func New() *Engine {
	return &Engine{ready: make(chan struct{})}
}

func (e *Engine) Ready() <-chan struct{} { return e.ready }

func (e *Engine) Addr() net.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.laddr
}

func (e *Engine) Run(ctx context.Context, opts Options) error {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return errors.New("ed2k: engine already running")
	}
	e.started = true
	e.opts = opts.withDefaults()
	e.mu.Unlock()

	if e.opts.Listen != "" {
		ln, err := net.Listen("tcp", e.opts.Listen)
		if err != nil {
			close(e.ready)
			return fmt.Errorf("ed2k: listen %s: %w", e.opts.Listen, err)
		}
		e.mu.Lock()
		e.ln = ln
		e.laddr = ln.Addr()
		e.mu.Unlock()
	}
	close(e.ready)

	logf := e.opts.Logf

	for _, addr := range e.opts.Servers {
		e.wg.Add(1)
		go e.dialServer(ctx, addr)
	}

	if e.ln != nil {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			ln := e.ln
			for {
				conn, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					logf("accept: %v", err)
					return
				}
				conn.Close()
			}
		}()
	}

	stopClose := context.AfterFunc(ctx, func() {
		e.mu.Lock()
		ln := e.ln
		e.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
	})
	defer stopClose()

	if len(e.opts.Servers) == 0 && e.ln == nil {
		<-ctx.Done()
		return nil
	}
	e.wg.Wait()
	return nil
}

func (e *Engine) ClientID() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clientID
}

func (e *Engine) IsLow() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lowID
}

func (e *Engine) IsLowID() bool { return e.IsLow() }

func (e *Engine) LowID() bool { return e.IsLow() }

func (e *Engine) TCPFlags() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tcpFlags
}

func (e *Engine) ServerFlags() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.serverFlags
}

func (e *Engine) ClientIP() [4]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clientIP
}

func (e *Engine) ServerList() []ServerEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ServerEntry, len(e.serverList))
	copy(out, e.serverList)
	return out
}

func (e *Engine) Messages() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.messages))
	copy(out, e.messages)
	return out
}

func (e *Engine) ServerMessages() []string { return e.Messages() }

func (e *Engine) Rejected() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rejected
}

func (e *Engine) RequestedServerList() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gotServerList
}

func (e *Engine) GotServerList() bool { return e.RequestedServerList() }
