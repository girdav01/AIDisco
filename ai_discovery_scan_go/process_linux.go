//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// getRunningProcesses returns a list of running processes by reading /proc.
func getRunningProcesses() []ProcessInfo {
	var procs []ProcessInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return procs
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		info := ProcessInfo{PID: pid}

		// Read process name from /proc/<pid>/comm
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm")); err == nil {
			info.Name = strings.TrimSpace(string(data))
		}

		// Read executable path from /proc/<pid>/exe symlink
		if exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe")); err == nil {
			info.Exe = exe
		}

		// Read command line from /proc/<pid>/cmdline (null-separated)
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline")); err == nil {
			info.CmdLine = strings.ReplaceAll(string(data), "\x00", " ")
			info.CmdLine = strings.TrimSpace(info.CmdLine)
		}

		if info.Name != "" {
			procs = append(procs, info)
		}
	}
	return procs
}
