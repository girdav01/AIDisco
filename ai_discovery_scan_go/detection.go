package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ---------------------------------------------------------------------------
// Legacy hardcoded detection methods (Ollama, LM Studio, GPT4All, vLLM)
// ---------------------------------------------------------------------------

func (s *Scanner) detectOllama() []DetectionResult {
	var results []DetectionResult
	home := userHomeDir()

	paths := map[string][]string{
		"windows": {
			filepath.Join(home, ".ollama"),
			filepath.Join(home, "AppData", "Local", "Programs", "Ollama"),
			`C:\Program Files\Ollama`,
			`C:\ollama`,
		},
		"darwin": {
			"/Applications/Ollama.app",
			filepath.Join(home, ".ollama"),
			"/usr/local/bin/ollama",
		},
		"linux": {
			"/usr/bin/ollama",
			"/usr/local/bin/ollama",
			"/usr/share/ollama",
			"/var/lib/ollama",
			filepath.Join(home, ".ollama"),
			filepath.Join(home, ".local", "bin", "ollama"),
		},
	}

	for _, p := range paths[runtime.GOOS] {
		if pathExists(p) {
			results = append(results, DetectionResult{
				Software: "Ollama", DetectionType: "file_path",
				Value: p, Path: p, Confidence: "high",
			})
		}
	}

	for _, v := range []string{"OLLAMA_MODELS", "OLLAMA_HOST", "OLLAMA_HOME"} {
		if val, ok := os.LookupEnv(v); ok {
			results = append(results, DetectionResult{
				Software: "Ollama", DetectionType: "environment_variable",
				Value: fmt.Sprintf("%s=%s", v, val), Confidence: "high",
			})
		}
	}

	results = append(results, s.detectProcessesByName("Ollama", []string{"ollama"})...)

	if checkPortOpen(11434) {
		results = append(results, DetectionResult{
			Software: "Ollama", DetectionType: "network_port",
			Value: "Port 11434 (HTTP API)", Confidence: "medium",
		})
	}

	if runtime.GOOS == "windows" {
		results = append(results, checkWindowsRegistryOllama()...)
	}
	return results
}

func (s *Scanner) detectLMStudio() []DetectionResult {
	var results []DetectionResult
	home := userHomeDir()

	paths := map[string][]string{
		"windows": {
			filepath.Join(home, "AppData", "Local", "LMStudio"),
			filepath.Join(home, "AppData", "Roaming", "LMStudio"),
			`C:\Program Files\LMStudio`,
			filepath.Join(home, ".cache", "lm-studio"),
			filepath.Join(home, ".lmstudio"),
		},
		"darwin": {
			"/Applications/LM Studio.app",
			filepath.Join(home, ".cache", "lm-studio"),
			filepath.Join(home, ".lmstudio"),
			filepath.Join(home, "Library", "Application Support", "LMStudio"),
		},
		"linux": {
			filepath.Join(home, ".cache", "lm-studio"),
			filepath.Join(home, ".lmstudio"),
			filepath.Join(home, "LMStudio"),
			"/opt/lmstudio",
		},
	}

	for _, p := range paths[runtime.GOOS] {
		if pathExists(p) {
			results = append(results, DetectionResult{
				Software: "LM Studio", DetectionType: "file_path",
				Value: p, Path: p, Confidence: "high",
			})
		}
	}

	for _, v := range []string{"LMSTUDIO_MODELS_DIR", "LM_STUDIO_HOME"} {
		if val, ok := os.LookupEnv(v); ok {
			results = append(results, DetectionResult{
				Software: "LM Studio", DetectionType: "environment_variable",
				Value: fmt.Sprintf("%s=%s", v, val), Confidence: "high",
			})
		}
	}

	results = append(results, s.detectProcessesByName("LM Studio", []string{"lmstudio", "lm-studio", "LMStudio"})...)

	if checkPortOpen(1234) {
		results = append(results, DetectionResult{
			Software: "LM Studio", DetectionType: "network_port",
			Value: "Port 1234 (HTTP API)", Confidence: "medium",
		})
	}

	if runtime.GOOS == "windows" {
		results = append(results, checkWindowsRegistryLMStudio()...)
	}
	return results
}

func (s *Scanner) detectGPT4All() []DetectionResult {
	var results []DetectionResult
	home := userHomeDir()

	paths := map[string][]string{
		"windows": {
			filepath.Join(home, "AppData", "Local", "GPT4All"),
			filepath.Join(home, "AppData", "Roaming", "GPT4All"),
			`C:\Program Files\GPT4All`,
			`C:\Program Files (x86)\GPT4All`,
			filepath.Join(home, ".gpt4all"),
			filepath.Join(home, "Documents", "GPT4All"),
			filepath.Join(home, "Downloads", "GPT4All"),
		},
		"darwin": {
			"/Applications/GPT4All.app",
			filepath.Join(home, "Applications", "GPT4All.app"),
			filepath.Join(home, ".gpt4all"),
			filepath.Join(home, "Library", "Application Support", "GPT4All"),
			filepath.Join(home, "Library", "Preferences", "GPT4All"),
		},
		"linux": {
			filepath.Join(home, ".gpt4all"),
			filepath.Join(home, ".local", "share", "gpt4all"),
			filepath.Join(home, "gpt4all"),
			"/opt/gpt4all",
			"/usr/local/gpt4all",
			filepath.Join(home, "Downloads", "gpt4all"),
		},
	}

	for _, p := range paths[runtime.GOOS] {
		if pathExists(p) {
			results = append(results, DetectionResult{
				Software: "GPT4All", DetectionType: "file_path",
				Value: p, Path: p, Confidence: "high",
			})
		}
	}

	for _, v := range []string{"GPT4ALL_MODEL_PATH", "GPT4ALL_HOME", "GPT4ALL_DATA_DIR"} {
		if val, ok := os.LookupEnv(v); ok {
			results = append(results, DetectionResult{
				Software: "GPT4All", DetectionType: "environment_variable",
				Value: fmt.Sprintf("%s=%s", v, val), Confidence: "high",
			})
		}
	}

	results = append(results, s.detectProcessesByName("GPT4All", []string{"gpt4all", "GPT4All", "gpt4all-app"})...)

	if checkPortOpen(4891) {
		results = append(results, DetectionResult{
			Software: "GPT4All", DetectionType: "network_port",
			Value: "Port 4891 (HTTP API)", Confidence: "medium",
		})
	}

	if runtime.GOOS == "windows" {
		results = append(results, checkWindowsRegistryGPT4All()...)
	}
	return results
}

func (s *Scanner) detectVLLM() []DetectionResult {
	var results []DetectionResult
	home := userHomeDir()

	paths := map[string][]string{
		"windows": {
			filepath.Join(home, "AppData", "Local", "vLLM"),
			filepath.Join(home, "AppData", "Roaming", "vLLM"),
			`C:\Program Files\vLLM`,
			filepath.Join(home, ".vllm"),
			filepath.Join(home, "vllm"),
			filepath.Join(home, "Documents", "vllm"),
		},
		"darwin": {
			filepath.Join(home, ".vllm"),
			filepath.Join(home, "vllm"),
			filepath.Join(home, "Library", "Application Support", "vLLM"),
			filepath.Join(home, "Library", "Preferences", "vLLM"),
		},
		"linux": {
			filepath.Join(home, ".vllm"),
			filepath.Join(home, "vllm"),
			"/opt/vllm",
			"/usr/local/vllm",
			filepath.Join(home, ".local", "share", "vllm"),
		},
	}

	for _, p := range paths[runtime.GOOS] {
		if pathExists(p) {
			results = append(results, DetectionResult{
				Software: "vLLM", DetectionType: "file_path",
				Value: p, Path: p, Confidence: "high",
			})
		}
	}

	for _, v := range []string{"VLLM_HOME", "VLLM_MODEL_PATH", "VLLM_DATA_DIR", "CUDA_VISIBLE_DEVICES"} {
		if val, ok := os.LookupEnv(v); ok {
			results = append(results, DetectionResult{
				Software: "vLLM", DetectionType: "environment_variable",
				Value: fmt.Sprintf("%s=%s", v, val), Confidence: "high",
			})
		}
	}

	results = append(results, s.detectProcessesByName("vLLM", []string{"vllm", "vllm-engine", "vllm-serve", "vllm-worker"})...)

	if checkPortOpen(8000) {
		results = append(results, DetectionResult{
			Software: "vLLM", DetectionType: "network_port",
			Value: "Port 8000 (HTTP API)", Confidence: "medium",
		})
	}

	if runtime.GOOS == "windows" {
		results = append(results, checkWindowsRegistryVLLM()...)
	}
	return results
}

// ---------------------------------------------------------------------------
// Generic detection helpers used by SIGMA-based detection
// ---------------------------------------------------------------------------

// detectProcessesByName scans running processes for matching names.
func (s *Scanner) detectProcessesByName(software string, patterns []string) []DetectionResult {
	var results []DetectionResult
	procs := getRunningProcesses()
	for _, proc := range procs {
		nameLower := strings.ToLower(proc.Name)
		for _, pattern := range patterns {
			cleaned := strings.TrimSuffix(strings.ReplaceAll(pattern, "\\", ""), ".exe")
			if strings.Contains(nameLower, strings.ToLower(cleaned)) {
				results = append(results, DetectionResult{
					Software:      software,
					DetectionType: "process",
					Value:         fmt.Sprintf("PID: %d, Name: %s", proc.PID, proc.Name),
					Path:          proc.Exe,
					Confidence:    "high",
				})
				break
			}
		}
	}
	return results
}

// detectProcessesByCmdLine scans running processes for matching command-line patterns.
func (s *Scanner) detectProcessesByCmdLine(software string, patterns []string) []DetectionResult {
	var results []DetectionResult
	procs := getRunningProcesses()
	for _, proc := range procs {
		cmdLower := strings.ToLower(proc.CmdLine)
		for _, pattern := range patterns {
			if strings.Contains(cmdLower, strings.ToLower(pattern)) {
				results = append(results, DetectionResult{
					Software:      software,
					DetectionType: "process",
					Value:         fmt.Sprintf("PID: %d, Name: %s, Cmd: %s", proc.PID, proc.Name, truncate(proc.CmdLine, 120)),
					Path:          proc.Exe,
					Confidence:    "high",
				})
				break
			}
		}
	}
	return results
}

// detectFilePaths checks whether any of the given path patterns exist on disk.
func (s *Scanner) detectFilePaths(software string, patterns []string) []DetectionResult {
	var results []DetectionResult
	home := userHomeDir()

	for _, pattern := range patterns {
		clean := strings.ReplaceAll(strings.ReplaceAll(pattern, "\\", ""), "/", "")
		candidates := []string{
			filepath.Join(home, clean),
		}
		if runtime.GOOS == "windows" {
			candidates = append(candidates,
				filepath.Join(home, "AppData", "Local", clean),
				filepath.Join(home, "AppData", "Roaming", clean),
				filepath.Join(`C:\Program Files`, clean),
				filepath.Join(`C:\Program Files (x86)`, clean),
			)
		}
		for _, p := range candidates {
			if pathExists(p) {
				results = append(results, DetectionResult{
					Software: software, DetectionType: "file_path",
					Value: p, Path: p, Confidence: "high",
				})
			}
		}
	}
	return results
}

// detectEnvVars checks environment variables against patterns.
func (s *Scanner) detectEnvVars(software string, patterns []string) []DetectionResult {
	var results []DetectionResult
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(key), strings.ToLower(pattern)) {
				results = append(results, DetectionResult{
					Software: software, DetectionType: "environment_variable",
					Value: env, Confidence: "high",
				})
				break
			}
		}
	}
	return results
}

// truncate shortens a string to maxLen, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
