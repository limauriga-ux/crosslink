//go:build darwin

package routetable

import (
	"syscall"

	"golang.org/x/net/route"
)

func startWatcher(onChange func()) (stop func(), err error) {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	// Set non-blocking so the goroutine can check the done channel.
	// We accept that a blocking read is also fine — Stop() will close
	// the fd causing the read to return with an error.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := syscall.Read(fd, buf)
			if err != nil {
				return
			}
			msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
			if err == nil && len(msgs) > 0 {
				onChange()
			}
		}
	}()
	return func() {
		close(done)
		// Close the fd so the blocked syscall.Read returns immediately.
		syscall.Close(fd)
	}, nil
}
