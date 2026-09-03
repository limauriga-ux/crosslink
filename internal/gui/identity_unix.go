//go:build darwin || linux

package gui

import "os"

func currentAuthorizedIDs() (uid, gid int) {
	return os.Getuid(), os.Getgid()
}
