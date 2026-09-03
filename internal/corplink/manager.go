package corplink

import (
	"sync"

	"github.com/limauriga-ux/crosslink/internal/config"
)

// Manager wraps Client + Session, used by the daemon.
type Manager struct {
	session *Session
	client  *Client
	mu      sync.Mutex
}

// NewManager loads session from path and creates a Manager.
func NewManager(sessionPath string) *Manager {
	return NewManagerWithConfig(sessionPath, config.DefaultConfig().Corplink)
}

func NewManagerWithConfig(sessionPath string, cfg config.CorplinkConfig) *Manager {
	s := LoadSession(sessionPath)
	return &Manager{
		session: s,
		client:  NewClientWithConfig(s, cfg),
	}
}

// IsAuthenticated reports whether the session has valid credentials.
func (m *Manager) IsAuthenticated() bool { return m.session.IsAuthenticated() }

// Session returns the underlying session.
func (m *Manager) Session() *Session { return m.session }

// Client returns the API client.
func (m *Manager) Client() *Client { return m.client }

func (m *Manager) Configure(cfg config.CorplinkConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.client.Configure(cfg)
}
