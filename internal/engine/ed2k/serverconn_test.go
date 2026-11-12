// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func waitCond(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met in time")
	}
}

func TestServerConnLowID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// read login
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_LOGINREQUEST {
			t.Errorf("login not received: %v %v", err, f.Opcode)
			return
		}
		// send low id
		ic := IDChange{NewID: 100, TCPFlags: 0x1234, ServerFlags: 7, ClientIP: [4]byte{1, 2, 3, 4}}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_IDCHANGE, Payload: ic.Marshal()}.Marshal())
		// expect getserverlist
		f2, err := readED2KFrame(conn)
		if err != nil || f2.Opcode != OP_GETSERVERLIST {
			t.Errorf("expected OP_GETSERVERLIST, got %v %v", err, f2.Opcode)
			return
		}
		// send server list
		sl := ServerList{Servers: []ServerEntry{{IP: [4]byte{5, 6, 7, 8}, Port: 4661}}}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SERVERLIST, Payload: sl.Marshal()}.Marshal())
		time.Sleep(50 * time.Millisecond)
	}()

	eng := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{Servers: []string{ln.Addr().String()}}) }()

	waitCond(t, 2*time.Second, func() bool { return eng.ClientID() == 100 })
	if !eng.IsLowID() {
		t.Fatal("want low id")
	}
	if eng.TCPFlags() != 0x1234 {
		t.Fatalf("tcp flags = %d", eng.TCPFlags())
	}
	if eng.ServerFlags() != 7 {
		t.Fatalf("server flags = %d", eng.ServerFlags())
	}
	if eng.ClientIP() != ([4]byte{1, 2, 3, 4}) {
		t.Fatalf("client ip = %v", eng.ClientIP())
	}
	if !eng.RequestedServerList() {
		t.Fatal("did not request server list")
	}
	waitCond(t, 2*time.Second, func() bool { return len(eng.ServerList()) == 1 })
	sl := eng.ServerList()
	if sl[0].Port != 4661 {
		t.Fatalf("port = %d", sl[0].Port)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestServerConnHighID(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_LOGINREQUEST {
			return
		}
		ic := IDChange{NewID: 16777216 + 5, TCPFlags: 9, ClientIP: [4]byte{9, 9, 9, 9}}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_IDCHANGE, Payload: ic.Marshal()}.Marshal())
		sl := ServerList{Servers: []ServerEntry{{IP: [4]byte{1, 1, 1, 1}, Port: 4662}, {IP: [4]byte{2, 2, 2, 2}, Port: 4663}}}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SERVERLIST, Payload: sl.Marshal()}.Marshal())
		time.Sleep(50 * time.Millisecond)
	}()

	eng := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{Servers: []string{ln.Addr().String()}}) }()

	waitCond(t, 2*time.Second, func() bool { return eng.ClientID() == 16777216+5 })
	if eng.IsLowID() {
		t.Fatal("want high id")
	}
	if eng.RequestedServerList() {
		t.Fatal("should not request server list for high id")
	}
	waitCond(t, 2*time.Second, func() bool { return len(eng.ServerList()) == 2 })

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestServerConnReject(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_LOGINREQUEST {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_REJECT, Payload: []byte{}}.Marshal())
	}()

	eng := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{Servers: []string{ln.Addr().String()}}) }()

	waitCond(t, 2*time.Second, func() bool { return eng.Rejected() })

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after reject")
	}
}

func TestServerConnServerMessage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_LOGINREQUEST {
			return
		}
		sm := ServerMessage{Message: "hello server"}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SERVERMESSAGE, Payload: sm.Marshal()}.Marshal())
		time.Sleep(50 * time.Millisecond)
	}()

	eng := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{Servers: []string{ln.Addr().String()}}) }()

	waitCond(t, 2*time.Second, func() bool {
		msgs := eng.ServerMessages()
		return len(msgs) == 1 && msgs[0] == "hello server"
	})

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestIsLowIDFunc(t *testing.T) {
	if !IsLowID(100) {
		t.Fatal("expected low")
	}
	if IsLowID(16777216 + 1) {
		t.Fatal("expected high")
	}
	if IsLowID(0) {
		t.Fatal("zero is not low")
	}
}
