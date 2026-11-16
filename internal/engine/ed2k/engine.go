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

	// Kad bootstrap node endpoints (UDP host:port). The fields below are
	// alias spellings resolved by kadBootstrapNodes.
	KadBootstrapNodes     []string
	KadBootstrapNode      []string
	KadBootstrapAddrs     []string
	KadBootstrapAddr      []string
	KadBootstrapAddresses []string
	KadBootstrapAddress   []string
	KadBootstrapPeers     []string
	KadBootstrapPeer      []string
	KadNodes              []string
	KadNode               []string
	KadBootstrapServers   []string
	KadBootstrapServer    []string
	BootstrapNodes        []string
	BootstrapNode         []string
	BootstrapAddrs        []string
	BootstrapAddr         []string
	BootstrapAddresses    []string
	BootstrapAddress      []string
	BootstrapPeers        []string
	BootstrapPeer         []string
	BootstrapList         []string
	KadBootstrapList      []string
}

func (o Options) withDefaults() Options {
	if o.Logf == nil {
		o.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "sharzad: ed2k: "+format+"\n", args...)
		}
	}
	if len(o.KadBootstrapNodes) == 0 {
		o.KadBootstrapNodes = o.kadBootstrapNodes()
	}
	return o
}

// kadBootstrapNodes resolves the alias fields into one canonical slice.
func (o Options) kadBootstrapNodes() []string {
	candidates := [][]string{
		o.KadBootstrapNodes,
		o.KadBootstrapNode,
		o.KadBootstrapAddrs,
		o.KadBootstrapAddr,
		o.KadBootstrapAddresses,
		o.KadBootstrapAddress,
		o.KadBootstrapPeers,
		o.KadBootstrapPeer,
		o.KadNodes,
		o.KadNode,
		o.KadBootstrapServers,
		o.KadBootstrapServer,
		o.BootstrapNodes,
		o.BootstrapNode,
		o.BootstrapAddrs,
		o.BootstrapAddr,
		o.BootstrapAddresses,
		o.BootstrapAddress,
		o.BootstrapPeers,
		o.BootstrapPeer,
		o.BootstrapList,
		o.KadBootstrapList,
	}
	for _, c := range candidates {
		if len(c) > 0 {
			out := make([]string, len(c))
			copy(out, c)
			return out
		}
	}
	return nil
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

	kadMu          sync.Mutex
	kadRoutingTable *KadRoutingTable
	kadTable       *KadRoutingTable
	routingTable   *KadRoutingTable
	kadRT          *KadRoutingTable
	kadSelf        [16]byte
	kadSelfID      [16]byte
	kadID          [16]byte
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

	// Prepare Kad self identity and routing table up front so callers can
	// observe them even before bootstrap completes.
	e.kadMu.Lock()
	if e.kadSelf == ([16]byte{}) && e.kadSelfID == ([16]byte{}) && e.kadID == ([16]byte{}) {
		e.kadSelf = newKadSelfID()
	}
	if e.kadSelf == ([16]byte{}) {
		if e.kadSelfID != ([16]byte{}) {
			e.kadSelf = e.kadSelfID
		} else if e.kadID != ([16]byte{}) {
			e.kadSelf = e.kadID
		}
	}
	if e.kadSelfID == ([16]byte{}) {
		e.kadSelfID = e.kadSelf
	}
	if e.kadID == ([16]byte{}) {
		e.kadID = e.kadSelf
	}
	if e.kadRoutingTable == nil {
		rt := NewKadRoutingTableWithSelf(e.kadSelf)
		e.kadRoutingTable = rt
		e.kadTable = rt
		e.routingTable = rt
		e.kadRT = rt
	}
	e.kadMu.Unlock()

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

	kadNodes := e.opts.kadBootstrapNodes()

	for _, addr := range e.opts.Servers {
		e.wg.Add(1)
		go e.dialServer(ctx, addr)
	}

	for _, node := range kadNodes {
		e.wg.Add(1)
		go func(n string) {
			defer e.wg.Done()
			addr, err := net.ResolveUDPAddr("udp", n)
			if err != nil {
				logf("kad bootstrap resolve %s: %v", n, err)
				return
			}

			e.kadMu.Lock()
			if e.kadSelf == ([16]byte{}) {
				e.kadSelf = newKadSelfID()
			}
			if e.kadSelfID == ([16]byte{}) {
				e.kadSelfID = e.kadSelf
			}
			if e.kadID == ([16]byte{}) {
				e.kadID = e.kadSelf
			}
			if e.kadRoutingTable == nil {
				rt := NewKadRoutingTableWithSelf(e.kadSelf)
				e.kadRoutingTable = rt
				e.kadTable = rt
				e.routingTable = rt
				e.kadRT = rt
			}
			table := e.kadRoutingTable
			self := e.kadSelf
			e.kadMu.Unlock()

			contacts, err := KadBootstrap(ctx, addr, self, table)
			if err != nil {
				logf("kad bootstrap %s: %v", n, err)
				return
			}
			for _, c := range contacts {
				table.Insert(c)
			}
			e.kadMu.Lock()
			e.kadRoutingTable = table
			e.kadTable = table
			e.routingTable = table
			e.kadRT = table
			e.kadMu.Unlock()
		}(node)
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

	if len(e.opts.Servers) == 0 && e.ln == nil && len(kadNodes) == 0 {
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
