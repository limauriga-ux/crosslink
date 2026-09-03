package corplink

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/limauriga-ux/crosslink/internal/managedfs"
)

// Session holds persistent auth state.
type Session struct {
	CompanyName string          `json:"company_name"`
	Server      string          `json:"server"`
	DeviceID    string          `json:"device_id"`
	DeviceName  string          `json:"device_name"`
	TOTPSecret  string          `json:"totp_secret,omitempty"`
	Cookies     []*SerialCookie `json:"cookies,omitempty"`

	path string
	mu   sync.Mutex
	jar  http.CookieJar
}

// SerialCookie is a JSON-serializable http.Cookie.
type SerialCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// LoadSession loads a session from path, or returns a new empty session.
func LoadSession(path string) *Session {
	s := &Session{path: path}
	if root, err := managedfs.Open(filepath.Dir(path), false); err == nil {
		if data, readErr := root.ReadFile(path, 1<<20); readErr == nil {
			json.Unmarshal(data, s) //nolint:errcheck
		}
		root.Close()
	}
	if s.DeviceID == "" {
		s.DeviceID = newUUID()
	}
	if s.DeviceName == "" {
		s.DeviceName = machineName()
	}
	s.rebuildJar()
	return s
}

// Save persists the session to disk.
func (s *Session) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncCookiesFromJarLocked()
	root, err := managedfs.Open(filepath.Dir(s.path), true)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return root.WriteFileAtomic(s.path, data, 0o600)
}

// Jar returns the cookie jar for HTTP requests.
func (s *Session) Jar() http.CookieJar {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jar
}

// IsAuthenticated reports whether an authentication cookie is present. The
// device identity cookies are transport metadata, not proof of login.
func (s *Session) IsAuthenticated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncCookiesFromJarLocked()
	return s.Server != "" && len(s.Cookies) > 0
}

// clearCredentialsLocked removes all persisted authentication state while
// retaining the stable device identity used by the next login.
func (s *Session) clearCredentialsLocked() {
	s.CompanyName = ""
	s.Server = ""
	s.TOTPSecret = ""
	s.Cookies = nil
	s.rebuildJar()
}

func isDeviceCookie(name string) bool {
	return name == "device_id" || name == "device_name"
}

func (s *Session) rebuildJar() {
	jar, _ := cookiejar.New(nil)
	if s.Server != "" {
		serverURL, err := url.Parse(s.Server)
		if err == nil {
			// Always inject device_id and device_name like corplink-rs does.
			// These identify the installation but do not authenticate it.
			var cookies []*http.Cookie
			if s.DeviceID != "" {
				cookies = append(cookies, &http.Cookie{Name: "device_id", Value: s.DeviceID, Path: "/"})
			}
			if s.DeviceName != "" {
				cookies = append(cookies, &http.Cookie{Name: "device_name", Value: s.DeviceName, Path: "/"})
			}
			// Append only saved authentication cookies. Older session files may
			// contain device cookies; ignore them during migration.
			for _, sc := range s.Cookies {
				if sc == nil || isDeviceCookie(sc.Name) {
					continue
				}
				cookies = append(cookies, &http.Cookie{
					Name: sc.Name, Value: sc.Value,
					Domain: sc.Domain, Path: sc.Path,
				})
			}
			jar.SetCookies(serverURL, cookies)
		}
	}
	s.jar = jar
}

// syncCookiesFromJarLocked copies only authentication cookies into the
// persisted representation. Set-Cookie responses may update device_id and
// device_name, so those values are folded back into their dedicated fields.
func (s *Session) syncCookiesFromJarLocked() {
	if s.Server == "" || s.jar == nil {
		return
	}
	serverURL, err := url.Parse(s.Server)
	if err != nil {
		return
	}
	s.Cookies = nil
	for _, c := range s.jar.Cookies(serverURL) {
		if c == nil || c.Value == "" {
			continue
		}
		switch c.Name {
		case "device_id":
			s.DeviceID = c.Value
			continue
		case "device_name":
			s.DeviceName = c.Value
			continue
		}
		s.Cookies = append(s.Cookies, &SerialCookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
		})
	}
}

func newUUID() string {
	b := make([]byte, 16)
	if f, err := os.Open("/dev/urandom"); err == nil {
		f.Read(b) //nolint:errcheck
		f.Close()
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func machineName() string {
	host, err := os.Hostname()
	if err != nil {
		return "macOS-device"
	}
	return "macOS-" + host
}
