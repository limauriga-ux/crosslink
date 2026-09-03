//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

func ensureAdmin() error {
	ret, _, _ := procIsUserAnAdmin.Call()
	if ret != 0 {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("permission denied: please run crosslink as Administrator")
	}

	// Build argument string, quoting args that contain spaces
	var args []string
	for i, a := range os.Args {
		if i == 0 {
			continue
		}
		if strings.Contains(a, " ") {
			args = append(args, `"`+a+`"`)
		} else {
			args = append(args, a)
		}
	}

	ret2, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("runas"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(exe))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(strings.Join(args, " ")))),
		0,
		uintptr(1), // SW_SHOWNORMAL
	)

	if ret2 > 32 {
		os.Exit(0)
	}

	return fmt.Errorf("permission denied: please run crosslink as Administrator")
}
