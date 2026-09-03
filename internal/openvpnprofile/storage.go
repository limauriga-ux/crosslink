package openvpnprofile

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SaveManaged atomically writes a validated profile beneath dataDir without
// following user-controlled symlinks. The daemon later reads this file as root,
// so lexical path containment alone is not a sufficient boundary.
func SaveManaged(dataDir, path string, profile Profile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	content, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("encode managed OpenVPN profile: %w", err)
	}
	content = append(content, '\n')
	if len(content) > MaxManagedBytes {
		return fmt.Errorf("managed OpenVPN profile exceeds %d bytes", MaxManagedBytes)
	}

	root, relative, err := openManagedRoot(dataDir, path, true)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, name, err := openManagedParent(root, relative, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	return replaceManagedFile(parent, name, content)
}

// LoadManaged reads a profile beneath dataDir without following symlinks and
// rejects files whose permissions expose the embedded private key.
func LoadManaged(dataDir, path string) (Profile, error) {
	root, relative, err := openManagedRoot(dataDir, path, false)
	if err != nil {
		return Profile{}, err
	}
	defer root.Close()
	parent, name, err := openManagedParent(root, relative, false)
	if err != nil {
		return Profile{}, err
	}
	defer parent.Close()

	info, err := parent.Lstat(name)
	if err != nil {
		return Profile{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Profile{}, fmt.Errorf("managed OpenVPN profile must be a regular file, not %s", info.Mode().Type())
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Profile{}, fmt.Errorf("managed OpenVPN profile permissions %04o expose private key material; require 0600", info.Mode().Perm())
	}
	if info.Size() > MaxManagedBytes {
		return Profile{}, fmt.Errorf("managed OpenVPN profile exceeds %d bytes", MaxManagedBytes)
	}
	file, err := parent.Open(name)
	if err != nil {
		return Profile{}, err
	}
	openedInfo, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, MaxManagedBytes+1))
	closeErr := file.Close()
	if statErr != nil {
		return Profile{}, statErr
	}
	if !os.SameFile(info, openedInfo) {
		return Profile{}, errors.New("managed OpenVPN profile changed while opening")
	}
	if readErr != nil {
		return Profile{}, readErr
	}
	if closeErr != nil {
		return Profile{}, closeErr
	}
	if len(content) > MaxManagedBytes {
		return Profile{}, fmt.Errorf("managed OpenVPN profile exceeds %d bytes", MaxManagedBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("parse managed OpenVPN profile: %w", err)
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// RemoveManaged removes the managed profile itself, never a symlink target.
func RemoveManaged(dataDir, path string) error {
	root, relative, err := openManagedRoot(dataDir, path, false)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, name, err := openManagedParent(root, relative, false)
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
		return errors.New("managed OpenVPN profile path is a directory")
	}
	return parent.Remove(name)
}

func openManagedRoot(dataDir, path string, create bool) (*os.Root, string, error) {
	dataDir, err := filepath.Abs(strings.TrimSpace(dataDir))
	if err != nil {
		return nil, "", fmt.Errorf("resolve CrossLink data directory: %w", err)
	}
	path, err = filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, "", fmt.Errorf("resolve managed OpenVPN profile: %w", err)
	}
	if filepath.Dir(dataDir) == dataDir {
		return nil, "", errors.New("CrossLink data directory cannot be a filesystem root")
	}
	relative, err := filepath.Rel(dataDir, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, "", fmt.Errorf("managed OpenVPN profile must be a file below %s", dataDir)
	}

	parentPath := filepath.Dir(dataDir)
	if create {
		if err := os.MkdirAll(parentPath, 0o700); err != nil {
			return nil, "", fmt.Errorf("create CrossLink data parent: %w", err)
		}
	}
	parentRoot, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, "", fmt.Errorf("open CrossLink data parent: %w", err)
	}
	defer parentRoot.Close()
	rootName := filepath.Base(dataDir)
	info, err := parentRoot.Lstat(rootName)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := parentRoot.Mkdir(rootName, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, "", fmt.Errorf("create CrossLink data directory: %w", err)
		}
		info, err = parentRoot.Lstat(rootName)
	}
	if err != nil {
		return nil, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, "", errors.New("CrossLink data directory must be a real directory")
	}
	root, err := parentRoot.OpenRoot(rootName)
	if err != nil {
		return nil, "", fmt.Errorf("open CrossLink data directory: %w", err)
	}
	if create {
		directory, openErr := root.Open(".")
		if openErr != nil {
			root.Close()
			return nil, "", openErr
		}
		chmodErr := directory.Chmod(0o700)
		closeErr := directory.Close()
		if chmodErr != nil {
			root.Close()
			return nil, "", chmodErr
		}
		if closeErr != nil {
			root.Close()
			return nil, "", closeErr
		}
	}
	return root, relative, nil
}

func openManagedParent(root *os.Root, relative string, create bool) (*os.Root, string, error) {
	name := filepath.Base(relative)
	if name == "." || name == "" {
		return nil, "", errors.New("managed OpenVPN profile name is empty")
	}
	parentPath := filepath.Dir(relative)
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	if parentPath == "." {
		return current, name, nil
	}
	for _, component := range strings.Split(parentPath, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, "", fmt.Errorf("invalid managed OpenVPN directory component %q", component)
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
			return nil, "", fmt.Errorf("managed OpenVPN directory %q must be a real directory", component)
		}
		next, openErr := current.OpenRoot(component)
		current.Close()
		if openErr != nil {
			return nil, "", openErr
		}
		current = next
		if create {
			directory, openErr := current.Open(".")
			if openErr != nil {
				current.Close()
				return nil, "", openErr
			}
			chmodErr := directory.Chmod(0o700)
			closeErr := directory.Close()
			if chmodErr != nil {
				current.Close()
				return nil, "", chmodErr
			}
			if closeErr != nil {
				current.Close()
				return nil, "", closeErr
			}
		}
	}
	return current, name, nil
}

func replaceManagedFile(root *os.Root, name string, content []byte) error {
	temporary, temporaryName, err := createManagedTemp(root)
	if err != nil {
		return err
	}
	defer root.Remove(temporaryName)
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
	return root.Rename(temporaryName, name)
}

func createManagedTemp(root *os.Root) (*os.File, string, error) {
	for range 10 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := fmt.Sprintf(".openvpn-%x.tmp", random)
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("create temporary OpenVPN profile: exhausted unique names")
}
