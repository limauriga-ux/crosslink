/* SPDX-License-Identifier: MIT */

package netstack

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestWriteNotifyStopsWhenDoneCloses(t *testing.T) {
	ep := channel.New(1, 1420, "")
	tun := &netTun{
		ep:             ep,
		incomingPacket: make(chan *buffer.View, 1),
		done:           make(chan struct{}),
	}

	queued := buffer.NewViewWithData([]byte{1})
	tun.incomingPacket <- queued

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{2}),
	})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	if n, err := ep.WritePackets(pkts); err != nil || n != 1 {
		pkt.DecRef()
		t.Fatalf("WritePackets = %d, %v; want 1, nil", n, err)
	}
	pkt.DecRef()

	notifyDone := make(chan struct{})
	go func() {
		tun.WriteNotify()
		close(notifyDone)
	}()

	deadline := time.Now().Add(time.Second)
	for ep.NumQueued() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ep.NumQueued() != 0 {
		t.Fatal("WriteNotify did not take ownership of the queued packet")
	}

	close(tun.done)
	select {
	case <-notifyDone:
	case <-time.After(time.Second):
		t.Fatal("WriteNotify remained blocked after done closed")
	}

	(<-tun.incomingPacket).Release()
	if got := len(tun.incomingPacket); got != 0 {
		t.Fatalf("incoming packet count = %d, want 0", got)
	}
}

func TestNetTunCloseUsesDoneWithoutClosingDataChannel(t *testing.T) {
	tdev, tnet, err := CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		nil,
		1420,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	tun := (*netTun)(tnet)

	tun.incomingPacket <- buffer.NewViewWithData([]byte{1})
	if err := tdev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tdev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	if _, err := tun.Read(bufs, sizes, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read error = %v, want os.ErrClosed", err)
	}

	late := buffer.NewViewWithData([]byte{2})
	select {
	case tun.incomingPacket <- late:
		view := <-tun.incomingPacket
		view.Release()
	default:
		late.Release()
		t.Fatal("incomingPacket was closed or unexpectedly full")
	}
}
