//go:build windows

package main

import (
	"encoding/csv"
	"os/exec"
	"strconv"
	"strings"
)

// getRunningProcesses returns a list of running processes using tasklist on Windows.
func getRunningProcesses() []ProcessInfo {
	var procs []ProcessInfo

	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return procs
	}

	reader := csv.NewReader(strings.NewReader(string(out)))
	records, err := reader.ReadAll()
	if err != nil {
		return procs
	}

	for _, record := range records {
		if len(record) < 2 {
			continue
		}
		name := strings.TrimSpace(record[0])
		pidStr := strings.TrimSpace(record[1])
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		procs = append(procs, ProcessInfo{
			PID:  pid,
			Name: name,
		})
	}

	// Try to get command lines via WMIC
	wout, err := exec.Command("wmic", "process", "get", "ProcessId,CommandLine", "/FORMAT:CSV").Output()
	if err == nil {
		cmdMap := make(map[int]string)
		lines := strings.Split(string(wout), "\n")
		for _, line := range lines[1:] { // skip header
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ",", 3)
			if len(parts) < 3 {
				continue
			}
			p, err := strconv.Atoi(strings.TrimSpace(parts[2]))
			if err != nil {
				continue
			}
			cmdMap[p] = strings.TrimSpace(parts[1])
		}
		for i := range procs {
			if cmd, ok := cmdMap[procs[i].PID]; ok {
				procs[i].CmdLine = cmd
			}
		}
	}

	return procs
}
