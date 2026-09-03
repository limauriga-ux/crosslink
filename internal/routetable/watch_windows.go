//go:build windows

package routetable

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func startWatcher(onChange func()) (stop func(), err error) {
	notifyCh := make(chan struct{}, 1)

	// The callback must match the PIPINTERFACE_CHANGE_CALLBACK signature:
	// VOID CALLBACK (*)(PVOID CallerContext, PMIB_IPFORWARD_ROW2 Row, MIB_NOTIFICATION_TYPE NotificationType)
	// We use syscall.NewCallback which creates a stdcall function pointer.
	cb := windows.NewCallback(func(callerCtx unsafe.Pointer, row unsafe.Pointer, notifType uint32) uintptr {
		select {
		case notifyCh <- struct{}{}:
		default:
		}
		return 0
	})

	var handle windows.Handle
	if err := windows.NotifyRouteChange2(windows.AF_UNSPEC, cb, nil, false, &handle); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				windows.CancelMibChangeNotify2(handle)
				return
			case <-notifyCh:
				onChange()
			}
		}
	}()
	return func() { close(done) }, nil
}
