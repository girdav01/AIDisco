//go:build !windows

package main

// detectWSL2AI is a no-op on non-Windows platforms.
// WSL2 is only available on Windows.
func (s *Scanner) detectWSL2AI() []DetectionResult {
	return nil
}
