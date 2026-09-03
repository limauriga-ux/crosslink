/* SPDX-License-Identifier: MIT */

package bindtest

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func openChannelBind(t *testing.T) (*ChannelBind, []conn.ReceiveFunc) {
	t.Helper()
	binds := NewChannelBinds()
	bind := binds[0].(*ChannelBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return bind, fns
}

func TestConcurrentCloseIsSafe(t *testing.T) {
	bind, _ := openChannelBind(t)

	const closers = 32
	start := make(chan struct{})
	done := make(chan error, closers)
	for i := 0; i < closers; i++ {
		go func() {
			<-start
			done <- bind.Close()
		}()
	}
	close(start)
	for i := 0; i < closers; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not return")
		}
	}
}

func TestCloseUnblocksBlockedSend(t *testing.T) {
	bind, _ := openChannelBind(t)
	for i := 0; i < cap(*bind.tx4); i++ {
		*bind.tx4 <- []byte{1}
	}

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- bind.Send([][]byte{{1}}, bind.target4)
	}()
	select {
	case err := <-sendDone:
		t.Fatalf("Send returned before Close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	if err := bind.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-sendDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Send error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Send did not return after Close")
	}
}

func TestOldReceiveFuncClosedAfterReopen(t *testing.T) {
	bind, first := openChannelBind(t)
	if err := bind.Close(); err != nil {
		t.Fatalf("Close generation 1: %v", err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open generation 2: %v", err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("Close generation 2: %v", err)
	}

	bufs := [][]byte{make([]byte, 8)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	if _, err := first[0](bufs, sizes, eps); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old ReceiveFunc error = %v, want net.ErrClosed", err)
	}
}

func TestOpenCloseRace(t *testing.T) {
	binds := NewChannelBinds()
	bind := binds[0].(*ChannelBind)
	for i := 0; i < 100; i++ {
		var wg sync.WaitGroup
		var openErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _, openErr = bind.Open(0)
		}()
		go func() {
			defer wg.Done()
			_ = bind.Close()
		}()
		wg.Wait()
		if openErr != nil && !errors.Is(openErr, conn.ErrBindAlreadyOpen) {
			t.Fatalf("Open: %v", openErr)
		}
		_ = bind.Close()
	}
}
