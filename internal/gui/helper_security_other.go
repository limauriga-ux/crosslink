//go:build !darwin && !linux

package gui

func isRootOwnedRegularFile(string) bool { return false }
