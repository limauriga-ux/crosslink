/* SPDX-License-Identifier: MIT */

package device

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type closeTestEndpoint struct{}

func (closeTestEndpoint) ClearSrc()           {}
func (closeTestEndpoint) SrcToString() string { return "" }
func (closeTestEndpoint) DstToString() string { return "127.0.0.1:1" }
func (closeTestEndpoint) DstToBytes() []byte  { return []byte{1} }
func (closeTestEndpoint) DstIP() netip.Addr   { return netip.MustParseAddr("127.0.0.1") }
func (closeTestEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type closeTestBind struct {
	sendStarted   chan struct{}
	sendReleased  chan struct{}
	closed        chan struct{}
	startOnce     sync.Once
	closeOnce     sync.Once
	openCalls     atomic.Int32
	closeCalls    atomic.Int32
	closeObserved atomic.Bool
}

var _ conn.Bind = (*closeTestBind)(nil)

func newCloseTestBind() *closeTestBind {
	return &closeTestBind{
		sendStarted:  make(chan struct{}),
		sendReleased: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (b *closeTestBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.openCalls.Add(1)
	return nil, 0, nil
}

func (b *closeTestBind) Close() error {
	b.closeCalls.Add(1)
	b.closeOnce.Do(func() {
		b.closeObserved.Store(true)
		close(b.closed)
		close(b.sendReleased)
	})
	return nil
}

func (b *closeTestBind) SetMark(uint32) error { return nil }

func (b *closeTestBind) Send([][]byte, conn.Endpoint) error {
	b.startOnce.Do(func() { close(b.sendStarted) })
	<-b.sendReleased
	return net.ErrClosed
}

func (b *closeTestBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return closeTestEndpoint{}, nil
}

func (b *closeTestBind) BatchSize() int { return 1 }

type blockedOpenBind struct {
	openStarted      chan struct{}
	openOnce         sync.Once
	mu               sync.Mutex
	openSignal       chan struct{}
	reopenAfterClose bool
	openCalls        atomic.Int32
	closeCalls       atomic.Int32
	closed           atomic.Bool
}

var _ conn.Bind = (*blockedOpenBind)(nil)

func newBlockedOpenBind(reopenAfterClose bool) *blockedOpenBind {
	return &blockedOpenBind{
		openStarted:      make(chan struct{}),
		reopenAfterClose: reopenAfterClose,
	}
}

func (b *blockedOpenBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.openCalls.Add(1)
	signal := make(chan struct{})
	b.mu.Lock()
	b.openSignal = signal
	b.closed.Store(false)
	b.mu.Unlock()
	b.openOnce.Do(func() { close(b.openStarted) })
	<-signal
	if b.reopenAfterClose {
		b.closed.Store(false)
		return nil, 0, nil
	}
	return nil, 0, net.ErrClosed
}

func (b *blockedOpenBind) Close() error {
	b.closeCalls.Add(1)
	b.mu.Lock()
	signal := b.openSignal
	b.openSignal = nil
	b.closed.Store(true)
	if signal != nil {
		close(signal)
	}
	b.mu.Unlock()
	return nil
}

func (b *blockedOpenBind) SetMark(uint32) error { return nil }
func (b *blockedOpenBind) Send([][]byte, conn.Endpoint) error {
	return net.ErrClosed
}
func (b *blockedOpenBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return closeTestEndpoint{}, nil
}
func (b *blockedOpenBind) BatchSize() int { return 1 }

type blockedSendGeneration struct {
	sendStarted  chan struct{}
	sendReleased chan struct{}
	startOnce    sync.Once
}

type blockedSendBind struct {
	mu         sync.Mutex
	generation *blockedSendGeneration
	closed     atomic.Bool
}

var _ conn.Bind = (*blockedSendBind)(nil)

func newBlockedSendBind() *blockedSendBind {
	return &blockedSendBind{}
}

func (b *blockedSendBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.generation != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.generation = &blockedSendGeneration{
		sendStarted:  make(chan struct{}),
		sendReleased: make(chan struct{}),
	}
	b.closed.Store(false)
	return nil, 0, nil
}

func (b *blockedSendBind) Close() error {
	b.mu.Lock()
	generation := b.generation
	b.generation = nil
	if generation != nil {
		b.closed.Store(true)
	}
	b.mu.Unlock()
	if generation != nil {
		close(generation.sendReleased)
	}
	return nil
}

func (b *blockedSendBind) SetMark(uint32) error { return nil }

func (b *blockedSendBind) Send([][]byte, conn.Endpoint) error {
	b.mu.Lock()
	generation := b.generation
	b.mu.Unlock()
	if generation == nil {
		return net.ErrClosed
	}
	generation.startOnce.Do(func() { close(generation.sendStarted) })
	<-generation.sendReleased
	return net.ErrClosed
}

func (b *blockedSendBind) generationStarted() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.generation == nil {
		return nil
	}
	return b.generation.sendStarted
}

func (b *blockedSendBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return closeTestEndpoint{}, nil
}

func (b *blockedSendBind) BatchSize() int { return 1 }

type closeTestTUN struct {
	bindClosed func() bool
	closed     chan struct{}
	events     chan tun.Event
	once       sync.Once
	order      atomic.Int32
}

var _ tun.Device = (*closeTestTUN)(nil)

func newCloseTestTUN(bind *closeTestBind) *closeTestTUN {
	return &closeTestTUN{
		bindClosed: func() bool { return bind.closeObserved.Load() },
		closed:     make(chan struct{}),
		events:     make(chan tun.Event),
	}
}

func newCloseTestTUNWithBindCheck(bindClosed func() bool) *closeTestTUN {
	return &closeTestTUN{
		bindClosed: bindClosed,
		closed:     make(chan struct{}),
		events:     make(chan tun.Event),
	}
}

func (t *closeTestTUN) File() *os.File { return nil }

func (t *closeTestTUN) Read([][]byte, []int, int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}

func (t *closeTestTUN) Write([][]byte, int) (int, error) { return 0, nil }
func (t *closeTestTUN) MTU() (int, error)                { return 1420, nil }
func (t *closeTestTUN) Name() (string, error)            { return "close-test", nil }
func (t *closeTestTUN) Events() <-chan tun.Event         { return t.events }
func (t *closeTestTUN) BatchSize() int                   { return 1 }

func (t *closeTestTUN) Close() error {
	t.once.Do(func() {
		if t.bindClosed != nil && !t.bindClosed() {
			t.order.Store(-1)
		} else {
			t.order.Store(1)
		}
		close(t.closed)
		close(t.events)
	})
	return nil
}

func TestClosePreClosesRawBindBeforeTUN(t *testing.T) {
	bind := newCloseTestBind()
	tunDev := newCloseTestTUN(bind)
	dev := NewDevice(tunDev, bind, NewLogger(LogLevelError, "close-test: "))

	peer, err := dev.NewPeer(NoisePublicKey{1})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	peer.SetEndpointFromPacket(closeTestEndpoint{})

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- peer.SendBuffers([][]byte{{1}})
	}()
	select {
	case <-bind.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("test bind Send did not start")
	}

	closeDone := make(chan struct{})
	go func() {
		dev.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Device.Close did not return after raw bind pre-close")
	}
	select {
	case err := <-sendDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Send error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Send was not released by raw bind pre-close")
	}

	if got := tunDev.order.Load(); got != 1 {
		t.Fatalf("TUN close order marker = %d, want 1 (bind must close first)", got)
	}
	select {
	case <-dev.Wait():
	default:
		t.Fatal("device Wait channel is not closed")
	}
}

func TestCloseDoesNotHangBehindBlockedBindUpdate(t *testing.T) {
	bind := newBlockedOpenBind(false)
	tunDev := newCloseTestTUNWithBindCheck(bind.closed.Load)
	dev := NewDevice(tunDev, bind, NewLogger(LogLevelError, "close-test: "))

	upDone := make(chan error, 1)
	go func() {
		upDone <- dev.Up()
	}()
	select {
	case <-bind.openStarted:
	case <-time.After(time.Second):
		t.Fatal("BindUpdate did not reach Open")
	}

	closeDone := make(chan struct{})
	go func() {
		dev.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Device.Close remained blocked behind BindUpdate")
	}
	select {
	case <-upDone:
	case <-time.After(time.Second):
		t.Fatal("BindUpdate did not finish after Close")
	}
	// This case does not reopen after the pre-close; the order check below is
	// intentionally only a teardown-order sanity check. The no-reopen fence
	// is covered by TestCloseReclosesBindReopenedByRacingBindUpdate.
	if got := tunDev.order.Load(); got != 1 {
		t.Fatalf("TUN close order marker = %d, want 1", got)
	}
}

func TestBindUpdateRefusesReopenWhileClosing(t *testing.T) {
	bind := newCloseTestBind()
	tunDev := newCloseTestTUN(bind)
	dev := NewDevice(tunDev, bind, NewLogger(LogLevelError, "close-test: "))

	if err := dev.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if got := bind.openCalls.Load(); got != 1 {
		t.Fatalf("Open calls after Up = %d, want 1", got)
	}
	dev.closing.Store(true)
	err := dev.BindUpdate()
	if !errors.Is(err, ErrDeviceClosing) {
		t.Fatalf("BindUpdate error = %v, want ErrDeviceClosing", err)
	}
	if got := bind.openCalls.Load(); got != 1 {
		t.Fatalf("Open calls after refused update = %d, want 1", got)
	}
	dev.Close()
}

func TestCloseReclosesBindReopenedByRacingBindUpdate(t *testing.T) {
	bind := newBlockedOpenBind(true)
	tunDev := newCloseTestTUNWithBindCheck(bind.closed.Load)
	dev := NewDevice(tunDev, bind, NewLogger(LogLevelError, "close-test: "))

	upDone := make(chan error, 1)
	go func() {
		upDone <- dev.Up()
	}()
	select {
	case <-bind.openStarted:
	case <-time.After(time.Second):
		t.Fatal("BindUpdate did not reach Open")
	}

	closeDone := make(chan struct{})
	go func() {
		dev.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Device.Close remained blocked behind racing BindUpdate")
	}
	select {
	case err := <-upDone:
		if err != nil {
			t.Fatalf("Up error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("BindUpdate did not finish after Close")
	}

	if got := bind.openCalls.Load(); got != 1 {
		t.Fatalf("Open calls = %d, want 1", got)
	}
	if got := bind.closeCalls.Load(); got < 4 {
		t.Fatalf("Close calls = %d, want at least 4", got)
	}
	if !bind.closed.Load() {
		t.Fatal("bind remained open at TUN teardown")
	}
	if got := tunDev.order.Load(); got != 1 {
		t.Fatalf("TUN close order marker = %d, want 1", got)
	}
	if err := dev.BindUpdate(); !errors.Is(err, ErrDeviceClosing) {
		t.Fatalf("post-Close BindUpdate error = %v, want ErrDeviceClosing", err)
	}
}

func TestConcurrentCloseIsSafe(t *testing.T) {
	bind := newCloseTestBind()
	tunDev := newCloseTestTUN(bind)
	dev := NewDevice(tunDev, bind, NewLogger(LogLevelError, "close-test: "))

	const closers = 16
	start := make(chan struct{})
	done := make(chan struct{}, closers)
	for i := 0; i < closers; i++ {
		go func() {
			<-start
			dev.Close()
			done <- struct{}{}
		}()
	}
	close(start)

	for i := 0; i < closers; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Device.Close did not return")
		}
	}
	select {
	case <-dev.Wait():
	case <-time.After(time.Second):
		t.Fatal("device Wait channel did not close")
	}
	if got := bind.closeCalls.Load(); got < closers {
		t.Fatalf("bind Close calls = %d, want at least %d", got, closers)
	}
}

func TestCloseUnblocksStateHolderBlockedOnNetLock(t *testing.T) {
	bind := newBlockedSendBind()
	tunDev := newCloseTestTUNWithBindCheck(bind.closed.Load)
	dev := NewDevice(tunDev, bind, NewLogger(LogLevelError, "close-test: "))

	if err := dev.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	peer, err := dev.NewPeer(NoisePublicKey{2})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	peer.SetEndpointFromPacket(closeTestEndpoint{})

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- peer.SendBuffers([][]byte{{1}})
	}()
	select {
	case <-bind.generationStarted():
	case <-time.After(time.Second):
		t.Fatal("test bind Send did not start")
	}

	downDone := make(chan error, 1)
	go func() {
		downDone <- dev.Down()
	}()
	deadline := time.Now().Add(time.Second)
	for dev.deviceState() != deviceStateDown && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dev.deviceState() != deviceStateDown {
		t.Fatal("Down did not publish the down state")
	}

	closeDone := make(chan struct{})
	go func() {
		dev.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Device.Close remained blocked behind state-held net lock")
	}
	select {
	case err := <-sendDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Send error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Send was not released by raw bind pre-close")
	}
	select {
	case err := <-downDone:
		if err != nil {
			t.Fatalf("Down error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Down did not finish after bind pre-close")
	}
	if got := tunDev.order.Load(); got != 1 {
		t.Fatalf("TUN close order marker = %d, want 1", got)
	}
	select {
	case <-dev.Wait():
	case <-time.After(time.Second):
		t.Fatal("device Wait channel did not close")
	}
}
