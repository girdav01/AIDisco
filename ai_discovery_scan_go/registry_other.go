//go:build !windows

package main

// Stub implementations for non-Windows platforms.

func checkWindowsRegistryOllama() []DetectionResult   { return nil }
func checkWindowsRegistryLMStudio() []DetectionResult  { return nil }
func checkWindowsRegistryGPT4All() []DetectionResult   { return nil }
func checkWindowsRegistryVLLM() []DetectionResult      { return nil }
func checkWindowsRegistryFromRule(_ string) []DetectionResult { return nil }
