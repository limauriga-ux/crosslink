//go:build darwin || linux

package managedfs

import (
	"io/fs"
	"syscall"
)

func ownerIDs(info fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
