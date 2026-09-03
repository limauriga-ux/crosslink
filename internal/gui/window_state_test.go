package gui

import "testing"

func TestValidWindowState(t *testing.T) {
	for _, state := range []WindowState{
		{Width: minWindowWidth, Height: minWindowHeight},
		{Width: defaultWindowWidth, Height: defaultWindowHeight},
		{Width: maxWindowWidth, Height: maxWindowHeight},
	} {
		if !validWindowState(state) {
			t.Fatalf("validWindowState(%+v) = false", state)
		}
	}
}

func TestInvalidWindowState(t *testing.T) {
	for _, state := range []WindowState{
		{Width: minWindowWidth - 1, Height: defaultWindowHeight},
		{Width: defaultWindowWidth, Height: minWindowHeight - 1},
		{Width: maxWindowWidth + 1, Height: defaultWindowHeight},
		{Width: defaultWindowWidth, Height: maxWindowHeight + 1},
	} {
		if validWindowState(state) {
			t.Fatalf("validWindowState(%+v) = true", state)
		}
	}
}
