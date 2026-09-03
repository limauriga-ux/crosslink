package managedfs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Root confines privileged file operations to one real directory tree.
// Every traversed directory and leaf is checked with Lstat before use; os.Root
// then prevents a concurrent symlink swap from escaping the tree.
type Root struct {
	path  string
	root  *os.Root
	owner Owner
}

// Open opens rootPath without following a symlink at the root itself. When
// create is true, a missing root is created owner-only and an existing root is
// tightened to 0700 through its opened descriptor.
func Open(rootPath string, create bool) (*Root, error) {
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" {
		return nil, errors.New("managed root is empty")
	}
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("resolve managed root: %w", err)
	}
	parentPath := filepath.Dir(absolute)
	if parentPath == absolute {
		return nil, errors.New("managed root cannot be a filesystem root")
	}
	if create {
		if err := os.MkdirAll(parentPath, 0o700); err != nil {
			return nil, fmt.Errorf("create managed root parent: %w", err)
		}
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, fmt.Errorf("open managed root parent: %w", err)
	}
	defer parent.Close()
	name := filepath.Base(absolute)
	info, err := parent.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := parent.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create managed root: %w", err)
		}
		info, err = parent.Lstat(name)
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("managed root must be a real directory")
	}
	opened, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open managed root: %w", err)
	}
	directory, err := opened.Open(".")
	if err != nil {
		opened.Close()
		return nil, err
	}
	openedInfo, statErr := directory.Stat()
	if statErr == nil && !os.SameFile(info, openedInfo) {
		statErr = errors.New("managed root changed while opening")
	}
	if statErr == nil && create {
		statErr = directory.Chmod(0o700)
	}
	if statErr == nil && !create && openedInfo.Mode().Perm()&0o022 != 0 {
		statErr = fmt.Errorf("managed root permissions %04o allow group/other writes", openedInfo.Mode().Perm())
	}
	uid, gid, ownerOK := ownerIDs(openedInfo)
	closeErr := directory.Close()
	if statErr != nil {
		opened.Close()
		return nil, statErr
	}
	if closeErr != nil {
		opened.Close()
		return nil, closeErr
	}
	owner := Owner{UID: -1, GID: -1}
	if ownerOK {
		owner = Owner{UID: uid, GID: gid}
	}
	return &Root{path: absolute, root: opened, owner: owner}, nil
}

func (r *Root) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	return r.root.Close()
}

func (r *Root) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Info returns metadata for the already-opened root directory. Callers use
// this instead of a path-based Stat when ownership is part of a privilege
// boundary.
func (r *Root) Info() (fs.FileInfo, error) {
	if r == nil || r.root == nil {
		return nil, errors.New("managed root is closed")
	}
	directory, err := r.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return directory.Stat()
}

func (r *Root) relative(path string) (string, error) {
	if r == nil || r.root == nil {
		return "", errors.New("managed root is closed")
	}
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(r.path, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("path must be a file below %s", r.path)
	}
	return relative, nil
}

func (r *Root) openParent(path string, create bool) (*os.Root, string, error) {
	relative, err := r.relative(path)
	if err != nil {
		return nil, "", err
	}
	name := filepath.Base(relative)
	parentPath := filepath.Dir(relative)
	current, err := r.root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	if parentPath == "." {
		return current, name, nil
	}
	for _, component := range strings.Split(parentPath, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, "", fmt.Errorf("invalid managed directory component %q", component)
		}
		info, statErr := current.Lstat(component)
		if errors.Is(statErr, fs.ErrNotExist) && create {
			if mkdirErr := current.Mkdir(component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
				current.Close()
				return nil, "", mkdirErr
			}
			info, statErr = current.Lstat(component)
		}
		if statErr != nil {
			current.Close()
			return nil, "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			current.Close()
			return nil, "", fmt.Errorf("managed directory %q must be a real directory", component)
		}
		next, openErr := current.OpenRoot(component)
		if openErr != nil {
			current.Close()
			return nil, "", openErr
		}
		directory, directoryErr := next.Open(".")
		if directoryErr == nil {
			var openedInfo fs.FileInfo
			openedInfo, directoryErr = directory.Stat()
			if directoryErr == nil && !os.SameFile(info, openedInfo) {
				directoryErr = fmt.Errorf("managed directory %q changed while opening", component)
			}
			if directoryErr == nil && create {
				directoryErr = directory.Chmod(0o700)
			}
			if closeErr := directory.Close(); directoryErr == nil {
				directoryErr = closeErr
			}
		}
		currentCloseErr := current.Close()
		if directoryErr != nil {
			next.Close()
			return nil, "", directoryErr
		}
		if currentCloseErr != nil {
			next.Close()
			return nil, "", currentCloseErr
		}
		current = next
	}
	return current, name, nil
}

// EnsureRegularFile creates or verifies a managed regular file without
// following a leaf symlink. Existing leaves are opened and compared with the
// lstat result before their permissions are tightened.
func (r *Root) EnsureRegularFile(path string, perm os.FileMode) error {
	return r.ensureRegularFile(path, perm, -1, -1)
}

// EnsureRegularFileOwned also applies ownership through the verified open
// descriptor before the file becomes a logging sink.
func (r *Root) EnsureRegularFileOwned(path string, perm os.FileMode, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return errors.New("managed file owner is invalid")
	}
	return r.ensureRegularFile(path, perm, uid, gid)
}

func (r *Root) ensureRegularFile(path string, perm os.FileMode, uid, gid int) error {
	parent, name, err := r.openParent(path, true)
	if err != nil {
		return err
	}
	defer parent.Close()

	info, statErr := parent.Lstat(name)
	var file *os.File
	if errors.Is(statErr, fs.ErrNotExist) {
		file, err = parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, fs.ErrExist) {
			return errors.New("managed file appeared while creating")
		}
	} else {
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("managed file must be a regular file, not %s", info.Mode().Type())
		}
		file, err = parent.OpenFile(name, os.O_WRONLY|os.O_APPEND, perm)
	}
	if err != nil {
		return err
	}

	openedInfo, verifyErr := file.Stat()
	if verifyErr == nil && !openedInfo.Mode().IsRegular() {
		verifyErr = fmt.Errorf("managed file must be a regular file, not %s", openedInfo.Mode().Type())
	}
	if verifyErr == nil && info != nil && !os.SameFile(info, openedInfo) {
		verifyErr = errors.New("managed file changed while opening")
	}
	if verifyErr == nil && uid >= 0 {
		verifyErr = file.Chown(uid, gid)
	}
	if verifyErr == nil {
		verifyErr = file.Chmod(perm)
	}
	closeErr := file.Close()
	if verifyErr != nil {
		return verifyErr
	}
	return closeErr
}

// ReadFile reads a regular non-symlink leaf and rejects content above limit.
func (r *Root) ReadFile(path string, limit int64) ([]byte, error) {
	parent, name, err := r.openParent(path, false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("managed file must be a regular file, not %s", info.Mode().Type())
	}
	if limit >= 0 && info.Size() > limit {
		return nil, fmt.Errorf("managed file exceeds %d bytes", limit)
	}
	file, err := parent.Open(name)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return nil, statErr
	}
	if !os.SameFile(info, openedInfo) {
		file.Close()
		return nil, errors.New("managed file changed while opening")
	}
	reader := io.Reader(file)
	if limit >= 0 {
		reader = io.LimitReader(file, limit+1)
	}
	content, readErr := io.ReadAll(reader)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if limit >= 0 && int64(len(content)) > limit {
		return nil, fmt.Errorf("managed file exceeds %d bytes", limit)
	}
	return content, nil
}

// WriteFileAtomic replaces a managed leaf without following an existing
// symlink. Root-owned privileged writers preserve a non-root managed-root
// owner so desktop clients retain access after an atomic replacement.
func (r *Root) WriteFileAtomic(path string, content []byte, perm os.FileMode) error {
	if r.owner.Valid() && os.Geteuid() == 0 && r.owner.UID != 0 {
		return r.writeFileAtomic(path, content, perm, r.owner.UID, r.owner.GID)
	}
	return r.writeFileAtomic(path, content, perm, -1, -1)
}

// WriteFileAtomicOwned applies ownership to the temporary inode before the
// atomic rename. It is useful when the target root is owned by a desktop user.
func (r *Root) WriteFileAtomicOwned(path string, content []byte, perm os.FileMode, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return errors.New("managed file owner is invalid")
	}
	return r.writeFileAtomic(path, content, perm, uid, gid)
}

func (r *Root) writeFileAtomic(path string, content []byte, perm os.FileMode, uid, gid int) error {
	parent, name, err := r.openParent(path, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	if info, statErr := parent.Lstat(name); statErr == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("managed file path is a directory")
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}
	temporary, temporaryName, err := createTemp(parent, perm)
	if err != nil {
		return err
	}
	defer parent.Remove(temporaryName)
	if uid >= 0 {
		if err := temporary.Chown(uid, gid); err != nil {
			temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return parent.Rename(temporaryName, name)
}

// Remove removes a managed non-directory leaf and is idempotent.
func (r *Root) Remove(path string) error {
	parent, name, err := r.openParent(path, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	info, err := parent.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("managed file path is a directory")
	}
	return parent.Remove(name)
}

func createTemp(root *os.Root, perm os.FileMode) (*os.File, string, error) {
	for range 10 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := fmt.Sprintf(".managed-%x.tmp", random)
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("create managed temporary file: exhausted unique names")
}
