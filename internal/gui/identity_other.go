//go:build !darwin && !linux

package gui

func currentAuthorizedIDs() (uid, gid int) {
	return -1, -1
}
