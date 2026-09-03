package conn

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTCPBindOpenReportsActualPortAndCloseIsIdempotent(t *testing.T) {
	bind := NewTCPBind().(*TcpBind)
	_, actualPort, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if actualPort == 0 {
		t.Fatal("Open(0) reported actualPort=0")
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestTCPBindSendRedialsAfterRemoteClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	bind := NewTCPBind().(*TcpBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("open bind: %v", err)
	}
	defer bind.Close()
	ep, err := bind.ParseEndpoint(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	if err := bind.Send([][]byte{[]byte("first")}, ep); err != nil {
		t.Fatalf("first send: %v", err)
	}
	first := <-accepted
	first.Close()

	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case second := <-accepted:
			second.Close()
			return
		case <-ticker.C:
			_ = bind.Send([][]byte{[]byte("second")}, ep)
		case <-deadline:
			t.Fatal("send did not redial after remote close")
		}
	}
}

func TestTCPBindConcurrentInitialSendDialsOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
			go io.Copy(io.Discard, conn) //nolint:errcheck
		}
	}()

	bind := NewTCPBind().(*TcpBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("open bind: %v", err)
	}
	defer bind.Close()
	ep, err := bind.ParseEndpoint(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- bind.Send([][]byte{[]byte("packet")}, ep)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if got := len(accepted); got != 1 {
		t.Fatalf("accepted connections = %d, want 1", got)
	}
}

func TestTCPBindReceiveBatchesBufferedPackets(t *testing.T) {
	const numPackets = 8

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		consumeFrame(conn)
		for i := 0; i < numPackets; i++ {
			payload := []byte{byte(i)}
			var hdr [4]byte
			binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
			if _, err := conn.Write(hdr[:]); err != nil {
				return
			}
			if _, err := conn.Write(payload); err != nil {
				return
			}
		}
		time.Sleep(time.Second)
	}()

	bind := NewTCPBind().(*TcpBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open bind: %v", err)
	}
	defer bind.Close()
	ep, err := bind.ParseEndpoint(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	if err := bind.Send([][]byte{[]byte("dummy")}, ep); err != nil {
		t.Fatalf("send dummy: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	bufs := make([][]byte, numPackets)
	for i := range bufs {
		bufs[i] = make([]byte, MaxSegmentSize)
	}
	sizes := make([]int, numPackets)
	eps := make([]Endpoint, numPackets)
	n, err := fns[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n <= 1 {
		t.Fatalf("receive returned %d packet(s), want a batch", n)
	}
}

func consumeFrame(conn net.Conn) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	size := binary.LittleEndian.Uint32(hdr[:])
	_, _ = io.CopyN(io.Discard, conn, int64(size))
}
