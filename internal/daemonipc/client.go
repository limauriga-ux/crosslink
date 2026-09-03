package daemonipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client sends commands to the daemon Unix socket.
type Client struct {
	path string
}

// NewClient creates a client for the given socket path.
func NewClient(socketPath string) *Client {
	return &Client{path: socketPath}
}

// Send sends a command and returns the response.
// Opens a new connection per call for simplicity.
func (c *Client) Send(cmd Cmd) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.path, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon socket: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck

	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("send command: %w", err)
	}

	var resp Response
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		return &resp, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no response received")
}
