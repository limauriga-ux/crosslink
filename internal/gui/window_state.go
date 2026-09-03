package gui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	// Sized from the user's preferred live window (~1183x848pt measured from
	// a screenshot including the ~28pt title bar).
	defaultWindowWidth  = 1180
	defaultWindowHeight = 820
	minWindowWidth      = 640
	minWindowHeight     = 400
	maxWindowWidth      = 2200
	maxWindowHeight     = 1600
)

func (s *Service) GetWindowState() WindowState {
	return LoadWindowState()
}

func (s *Service) SaveWindowState(state WindowState) CommandResult {
	if !validWindowState(state) {
		return CommandResult{OK: false, Summary: "invalid window size"}
	}
	path := WindowStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return CommandResult{OK: false, Summary: err.Error()}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return CommandResult{OK: false, Summary: err.Error()}
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return CommandResult{OK: false, Summary: err.Error()}
	}
	return CommandResult{OK: true}
}

func LoadWindowState() WindowState {
	state := WindowState{Width: defaultWindowWidth, Height: defaultWindowHeight}
	data, err := os.ReadFile(WindowStatePath())
	if err != nil {
		return state
	}
	var saved WindowState
	if err := json.Unmarshal(data, &saved); err != nil || !validWindowState(saved) {
		return state
	}
	return saved
}

func WindowStatePath() string {
	return filepath.Join(defaultCrosslinkDir(), "gui_state.json")
}

func validWindowState(state WindowState) bool {
	return state.Width >= minWindowWidth &&
		state.Height >= minWindowHeight &&
		state.Width <= maxWindowWidth &&
		state.Height <= maxWindowHeight
}
