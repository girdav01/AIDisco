package main

import (
	"context"
	"os/exec"
	"time"
)

const subprocessTimeout = 30 * time.Second

// runCommandTimeout runs a command with a timeout and returns its stdout.
func runCommandTimeout(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
