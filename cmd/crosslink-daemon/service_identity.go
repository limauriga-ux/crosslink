package main

import "strconv"

func daemonIdentityArgs(uid, gid int, rootOnly bool) []string {
	if rootOnly {
		return []string{"--root-only"}
	}
	if uid < 0 || gid < 0 {
		return nil
	}
	return []string{"--user-uid", strconv.Itoa(uid), "--user-gid", strconv.Itoa(gid)}
}
