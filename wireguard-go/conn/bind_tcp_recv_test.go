package conn

// TestTCPBindRecvNoCorruption verifies that the TCP receive path does NOT corrupt
// or alias packet buffers when multiple framed packets arrive back-to-back.
//
// Background: handleConn took a single *recvData from the pool ONCE per
// connection and reused its buffer for every packet, sending the same pointer
// into recvChan each iteration. While that pointer sat in the (1024-buffered)
// channel, the read loop overwrote data.buff with the next packet. The consumer
// in makeReceive therefore copied out whatever the LAST read left behind — every
// inbound WireGuard ciphertext was clobbered, failed Poly1305 auth, and was
// dropped, collapsing download throughput on TCP nodes.
//
// This test sends N distinct framed packets, lets the read loop drain them into
// the channel, THEN reads them back — deterministically exposing the aliasing.

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPBindRecvNoCorruption(t *testing.T) {
	const numPackets = 100

	// distinct payload per packet: packet i is filled with byte i and has a
	// distinct length, so any aliasing shows up as wrong content or wrong size.
	makePayload := func(i int) []byte {
		size := 1300 + i // all <= MaxSegmentSize
		p := make([]byte, size)
		for j := range p {
			p[j] = byte(i)
		}
		return p
	}

	// Server that, once connected, first consumes one framing dummy frame, then
	// writes numPackets distinct framed packets as fast as possible.
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
		// Consume the dummy frame that bind.Send emits to trigger the dial.
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		dummyLen := int(binary.LittleEndian.Uint32(hdr[:]))
		if _, err := io.ReadFull(conn, make([]byte, dummyLen)); err != nil {
			return
		}
		// Write all distinct framed packets back-to-back.
		for i := 0; i < numPackets; i++ {
			p := makePayload(i)
			var lh [4]byte
			binary.LittleEndian.PutUint32(lh[:], uint32(len(p)))
			if _, err := conn.Write(lh[:]); err != nil {
				return
			}
			if _, err := conn.Write(p); err != nil {
				return
			}
		}
		// Keep the connection open so the read loop doesn't tear down.
		time.Sleep(2 * time.Second)
	}()

	bind := NewTCPBind().(*TcpBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer bind.Close()
	recv := fns[0]

	endpoint, err := bind.ParseEndpoint(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	// Trigger dial + handleConn by sending a dummy packet.
	if err := bind.Send([][]byte{[]byte("hello-dummy")}, endpoint); err != nil {
		t.Fatalf("send dummy: %v", err)
	}

	// Give the read loop time to drain all numPackets frames into recvChan.
	// Under the bug, by now the single shared buffer holds packet #99's bytes,
	// and every channel entry aliases it.
	time.Sleep(300 * time.Millisecond)

	// Read packets back and verify each matches its distinct expected content.
	bufs := [][]byte{make([]byte, MaxSegmentSize)}
	sizes := []int{0}
	eps := make([]Endpoint, 1)

	corrupt := 0
	for i := 0; i < numPackets; i++ {
		n, err := recv(bufs, sizes, eps)
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("recv[%d]: got n=%d, want 1", i, n)
		}
		want := makePayload(i)
		got := bufs[0][:sizes[0]]
		if sizes[0] != len(want) || got[0] != byte(i) {
			corrupt++
			if corrupt <= 5 {
				t.Logf("packet %d corrupted: got size=%d firstByte=%d, want size=%d firstByte=%d",
					i, sizes[0], got[0], len(want), byte(i))
			}
		}
	}
	if corrupt > 0 {
		t.Errorf("%d/%d received packets were corrupted/aliased (buffer reuse race)",
			corrupt, numPackets)
	}
}
