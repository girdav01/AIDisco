//go:build darwin

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// getRunningProcesses returns a list of running processes using the ps command on macOS.
func getRunningProcesses() []ProcessInfo {
	var procs []ProcessInfo

	out, err := exec.Command("ps", "-eo", "pid,comm,args").Output()
	if err != nil {
		return procs
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 { // skip header
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		info := ProcessInfo{
			PID:  pid,
			Name: fields[1],
		}

		if len(fields) > 2 {
			info.CmdLine = strings.Join(fields[2:], " ")
			info.Exe = fields[2]
		}

		procs = append(procs, info)
	}
	return procs
}
