//go:build !darwin && !linux

package managedfs

import "io/fs"

func ownerIDs(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
