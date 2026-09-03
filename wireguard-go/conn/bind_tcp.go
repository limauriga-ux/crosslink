package conn

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"
)

var (
	_ Bind = (*TcpBind)(nil)
)

// MaxSegmentSize ref: device.MaxSegmentSize, we choose the max
const MaxSegmentSize = 65535

func NewTCPBind() Bind {
	return &TcpBind{
		dataPool: sync.Pool{
			New: func() any {
				data := &recvData{
					buff: make([]byte, MaxSegmentSize),
				}
				return data
			},
		},
	}
}

type TcpBind struct {
	mu         sync.Mutex
	tcpConnMap map[string]*tcpConn
	dialing    map[string]*sync.Mutex
	listener   *net.TCPListener
	closed     bool
	fwmark     uint32

	dataPool  sync.Pool
	recvChan  chan *recvData
	closeChan chan struct{}
}

type tcpConn struct {
	conn    *net.TCPConn
	writeMu sync.Mutex
}

type reqLen [4]byte

func (l *reqLen) Len() int {
	return int(l[0]) + int(l[1])<<8 + int(l[2])<<16 + int(l[3])<<24
}

func (l *reqLen) FromLen(len int) {
	l[0] = byte(len & 0xff)
	l[1] = byte(len >> 8 & 0xff)
	l[2] = byte(len >> 16 & 0xff)
	l[3] = byte(len >> 24 & 0xff)
}

type recvData struct {
	len      [4]byte
	buff     []byte
	size     int
	endpoint Endpoint
}

func (t *TcpBind) makeReceive() ReceiveFunc {
	closeChan := t.closeChan
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		if len(bufs) == 0 {
			return 0, nil
		}

		count := 0
		select {
		case <-closeChan:
			return 0, net.ErrClosed
		case data := <-t.recvChan:
			count = t.copyReceivedData(bufs, sizes, eps, count, data)
		}
		for count < len(bufs) {
			select {
			case data := <-t.recvChan:
				count = t.copyReceivedData(bufs, sizes, eps, count, data)
			default:
				return count, nil
			}
		}
		return count, nil
	}
}

func (t *TcpBind) copyReceivedData(bufs [][]byte, sizes []int, eps []Endpoint, count int, data *recvData) int {
	if data == nil {
		return count
	}
	sizes[count] = data.size
	copy(bufs[count], data.buff[:sizes[count]])
	eps[count] = data.endpoint
	// Return the buffer to the pool only AFTER copying its contents out.
	// handleConn hands us a fresh buffer per packet; recycling it here
	// (not in handleConn's loop) is what keeps the buffer from being
	// overwritten while still in flight.
	t.dataPool.Put(data)
	return count + 1
}

func (t *TcpBind) handleConn(entry *tcpConn, endpoint Endpoint) {
	closeChan := t.closeChan
	go func() {
		defer func() {
			t.deleteConn(endpoint.DstToString(), entry)
			entry.conn.Close()
		}()
		for {
			// Take a FRESH buffer per packet. Reusing one buffer across the
			// loop aliases every in-flight packet to the same memory: while a
			// pointer waits in recvChan the next read overwrites its bytes, so
			// the consumer copies out the wrong (last-read) packet. That
			// corrupts every inbound WireGuard ciphertext → Poly1305 auth fails
			// → packet dropped → download throughput collapses. The consumer
			// (makeReceive) returns this buffer to the pool after copying.
			data := t.dataPool.Get().(*recvData)
			// read uint32 size header
			_, err := io.ReadFull(entry.conn, data.len[:])
			if err != nil {
				t.dataPool.Put(data)
				return
			}
			l := reqLen(data.len)
			size := l.Len()
			// Guard against a malformed/desynced length: data.buff is
			// MaxSegmentSize bytes, so a larger size would panic on the slice
			// below. A bad frame means the stream is unrecoverable; tear down.
			if size < 0 || size > len(data.buff) {
				t.dataPool.Put(data)
				return
			}
			// read real data
			n, err := io.ReadFull(entry.conn, data.buff[:size])
			if err != nil {
				t.dataPool.Put(data)
				return
			}
			if n != size {
				t.dataPool.Put(data)
				continue
			}
			data.size = size
			data.endpoint = endpoint
			select {
			case <-closeChan:
				t.dataPool.Put(data)
				return
			case t.recvChan <- data:
			}
		}
	}()
}

func (t *TcpBind) deleteConn(endpoint string, entry *tcpConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tcpConnMap != nil && t.tcpConnMap[endpoint] == entry {
		delete(t.tcpConnMap, endpoint)
	}
}

func (t *TcpBind) accept(listener *net.TCPListener) {
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		conn.SetNoDelay(true) //nolint:errcheck
		if err := t.applyMark(conn); err != nil {
			conn.Close()
			continue
		}
		addrPort := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		endpoint := &StdNetEndpoint{AddrPort: addrPort}
		entry := &tcpConn{conn: conn}
		t.storeConn(endpoint.DstToString(), entry)
		t.handleConn(entry, endpoint)
	}
}

func (t *TcpBind) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recvChan = make(chan *recvData, 1024) // buffered: prevent HoL blocking on receive
	t.closeChan = make(chan struct{})
	t.tcpConnMap = make(map[string]*tcpConn)
	t.dialing = make(map[string]*sync.Mutex)
	t.closed = false

	t.listener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	go t.accept(t.listener)
	fn := t.makeReceive()
	actualPort = uint16(t.listener.Addr().(*net.TCPAddr).Port)
	return []ReceiveFunc{fn}, actualPort, nil
}

func (t *TcpBind) Close() error {
	var err error
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	conns := make([]*tcpConn, 0, len(t.tcpConnMap))
	for _, entry := range t.tcpConnMap {
		conns = append(conns, entry)
	}
	t.tcpConnMap = nil
	listener := t.listener
	t.listener = nil
	closeChan := t.closeChan
	t.closeChan = nil
	t.mu.Unlock()

	for _, entry := range conns {
		e := entry.conn.Close()
		if e != nil {
			err = e
		}
	}
	if listener != nil {
		_ = listener.Close()
	}
	if closeChan != nil {
		close(closeChan)
	}
	return err
}

func (t *TcpBind) storeConn(endpoint string, entry *tcpConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		entry.conn.Close()
		return
	}
	if t.tcpConnMap == nil {
		t.tcpConnMap = make(map[string]*tcpConn)
	}
	if old := t.tcpConnMap[endpoint]; old != nil && old != entry {
		old.conn.Close()
	}
	t.tcpConnMap[endpoint] = entry
}

func (t *TcpBind) getConn(endpoint Endpoint) (*tcpConn, error) {
	endpointKey := endpoint.DstToString()
	conn, ok := t.loadConn(endpointKey)
	if ok {
		return conn, nil
	}

	dialLock := t.dialLock(endpointKey)
	dialLock.Lock()
	defer dialLock.Unlock()
	if t.isClosed() {
		return nil, net.ErrClosed
	}
	conn, ok = t.loadConn(endpointKey)
	if ok {
		return conn, nil
	}

	ip := make(net.IP, net.IPv6len)
	if endpoint.DstIP().Is6() {
		as16 := endpoint.DstIP().As16()
		copy(ip, as16[:])
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ip, as4[:])
		ip = ip[:4]
	}
	addr := &net.TCPAddr{
		IP:   ip,
		Port: int(endpoint.(*StdNetEndpoint).Port()),
	}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := dialer.Dial("tcp", addr.String())
	if err != nil {
		return nil, err
	}
	rawTCP := rawConn.(*net.TCPConn)
	// Disable Nagle's algorithm: without this, the two-write protocol (4-byte
	// length header followed by payload) causes each WireGuard packet to be
	// delayed by one RTT while the kernel waits for the header's ACK before
	// sending the payload. On a 100ms China→Singapore path this caps throughput
	// to ~14 KB/s regardless of available bandwidth.
	rawTCP.SetNoDelay(true) //nolint:errcheck
	if err := t.applyMark(rawTCP); err != nil {
		rawTCP.Close()
		return nil, err
	}
	entry := &tcpConn{conn: rawTCP}
	t.storeConn(endpointKey, entry)
	t.handleConn(entry, endpoint)
	return entry, nil
}

func (t *TcpBind) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *TcpBind) loadConn(endpoint string) (*tcpConn, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.tcpConnMap == nil {
		return nil, false
	}
	conn, ok := t.tcpConnMap[endpoint]
	return conn, ok
}

func (t *TcpBind) dialLock(endpoint string) *sync.Mutex {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dialing == nil {
		t.dialing = make(map[string]*sync.Mutex)
	}
	lock := t.dialing[endpoint]
	if lock == nil {
		lock = &sync.Mutex{}
		t.dialing[endpoint] = lock
	}
	return lock
}

func (t *TcpBind) Send(bufs [][]byte, endpoint Endpoint) error {
	entry, err := t.getConn(endpoint)
	if err != nil {
		return err
	}
	entry.writeMu.Lock()
	defer entry.writeMu.Unlock()
	for _, buf := range bufs {
		var l reqLen
		l.FromLen(len(buf))
		// Write length header and payload in one vectored write. Separate Write
		// calls can interact badly with Nagle; writev-style emission avoids the
		// delay without allocating a new header+payload buffer per packet.
		msg := net.Buffers{l[:], buf}
		n, err := msg.WriteTo(entry.conn)
		if err != nil || n != int64(4+len(buf)) {
			t.deleteConn(endpoint.DstToString(), entry)
			entry.conn.Close()
			if err != nil {
				return err
			}
			return io.ErrShortWrite
		}
	}
	return nil
}

func (t *TcpBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (t *TcpBind) BatchSize() int {
	if runtime.GOOS == "linux" {
		return IdealBatchSize
	}
	return 1
}
