package daemonipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Handler processes a command and returns a response.
type Handler func(cmd Cmd) Response

// Server listens on a Unix socket and dispatches commands.
type Server struct {
	path          string
	authorizedUID int
	authorizedGID int
	handler       Handler
	ln            net.Listener
	closeOnce     sync.Once
	wg            sync.WaitGroup
}

// NewServer creates a server for the current process identity. Production
// privileged daemons must use NewServerWithAuthorizedOwner so the desktop
// user's UID is explicit and checked against the opened data root.
func NewServer(socketPath string, handler Handler) *Server {
	uid, gid := defaultAuthorizedOwner()
	return NewServerWithAuthorizedOwner(socketPath, uid, gid, handler)
}

// NewServerWithAuthorizedOwner binds IPC authorization and socket ownership to
// an identity selected by the caller. The server never derives authorization
// from the socket directory after accepting a connection.
func NewServerWithAuthorizedOwner(socketPath string, uid, gid int, handler Handler) *Server {
	return &Server{path: socketPath, authorizedUID: uid, authorizedGID: gid, handler: handler}
}

// Start begins listening. Non-blocking.
func (s *Server) Start() error {
	path := strings.TrimSpace(s.path)
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("daemon socket path must be absolute")
	}
	s.path = filepath.Clean(path)
	parent := filepath.Dir(s.path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("daemon socket parent must be a real directory")
	}
	if info, statErr := os.Lstat(s.path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to replace symlink at daemon socket path")
		}
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket at daemon socket path")
		}
		// A socket is safe to remove only after confirming it is not serving.
		// Ordinary files, directories, and links are always fail-closed above.
		if probe, dialErr := net.DialTimeout("unix", s.path, 100*time.Millisecond); dialErr == nil {
			probe.Close()
			return errors.New("daemon socket is already in use")
		}
		if err := os.Remove(s.path); err != nil {
			return fmt.Errorf("remove stale daemon socket: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	if err := configureSocketOwner(ln, s.authorizedUID, s.authorizedGID); err != nil {
		if closeErr := ln.Close(); closeErr != nil {
			return fmt.Errorf("secure daemon socket: %w (close listener: %v)", err, closeErr)
		}
		if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("secure daemon socket: %w (remove socket: %v)", err, removeErr)
		}
		return fmt.Errorf("secure daemon socket: %w", err)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.accept()
	return nil
}

// StopAccepting closes the listener without waiting for in-flight handlers.
// Shutdown uses this before VPN teardown so no new privileged command can
// enter while lifecycle state is being dismantled.
func (s *Server) StopAccepting() {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			s.ln.Close()
		}
	})
}

// Wait waits for the accept loop and all in-flight handlers to finish.
func (s *Server) Wait() {
	s.wg.Wait()
}

// Stop closes the listener and waits for connections to finish.
func (s *Server) Stop() {
	s.StopAccepting()
	s.Wait()
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.handle(c)
		}(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	if err := validatePeer(conn, s.authorizedUID); err != nil {
		log.Printf("[daemonipc] rejected peer: %v", err)
		return
	}
	scanner := bufio.NewScanner(conn)
	enc := json.NewEncoder(conn)
	for scanner.Scan() {
		var cmd Cmd
		if err := json.Unmarshal(scanner.Bytes(), &cmd); err != nil {
			enc.Encode(Response{OK: false, Error: "invalid JSON: " + err.Error()}) //nolint:errcheck
			continue
		}
		resp := s.handler(cmd)
		if err := enc.Encode(resp); err != nil {
			log.Printf("[daemonipc] write response: %v", err)
			return
		}
	}
}
