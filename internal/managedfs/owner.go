package managedfs

// Owner identifies the numeric owner of an already-opened managed root.
// UID/GID are -1 when the host platform cannot expose them.
type Owner struct {
	UID int
	GID int
}

func (o Owner) Valid() bool { return o.UID >= 0 && o.GID >= 0 }

// Owner returns ownership metadata from the opened root descriptor. It does
// not re-resolve the root path, so a caller can use it as a privilege-boundary
// check after Open has rejected symlink escapes.
func (r *Root) Owner() (Owner, error) {
	info, err := r.Info()
	if err != nil {
		return Owner{}, err
	}
	uid, gid, ok := ownerIDs(info)
	if !ok {
		return Owner{UID: -1, GID: -1}, nil
	}
	return Owner{UID: uid, GID: gid}, nil
}
