package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// loadSigmaRules loads all .yml files from the SIGMA rules directory.
func (s *Scanner) loadSigmaRules() error {
	s.SigmaRules = nil

	info, err := os.Stat(s.SigmaRulesDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("SIGMA rules directory not found: %s", s.SigmaRulesDir)
	}

	entries, err := filepath.Glob(filepath.Join(s.SigmaRulesDir, "*.yml"))
	if err != nil {
		return fmt.Errorf("failed to glob SIGMA rules: %w", err)
	}

	if len(entries) > 100 {
		log.Printf("Warning: too many SIGMA rule files (%d), limiting to 100", len(entries))
		entries = entries[:100]
	}

	for _, path := range entries {
		fi, err := os.Stat(path)
		if err != nil || fi.Size() > maxFileSize {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Warning: could not read %s: %v", path, err)
			continue
		}

		var rule SigmaRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			log.Printf("Warning: could not parse %s: %v", path, err)
			continue
		}

		if rule.Title != "" {
			s.SigmaRules = append(s.SigmaRules, rule)
		}
	}

	log.Printf("Loaded %d SIGMA rules", len(s.SigmaRules))
	return nil
}

// applySigmaRules matches detection results against loaded SIGMA rules.
func (s *Scanner) applySigmaRules(results []DetectionResult) []SigmaMatch {
	var matches []SigmaMatch
	for _, rule := range s.SigmaRules {
		for _, result := range results {
			if ruleMatchesResult(rule, result) {
				matches = append(matches, SigmaMatch{
					RuleID:    rule.ID,
					RuleTitle: rule.Title,
					Detection: SigmaDetection{
						Software: result.Software,
						Type:     result.DetectionType,
						Value:    result.Value,
					},
					Level: rule.Level,
				})
			}
		}
	}
	return matches
}

// ruleMatchesResult does a simplified check of whether a rule matches a detection result.
func ruleMatchesResult(rule SigmaRule, result DetectionResult) bool {
	detection := rule.Detection
	if detection == nil {
		return false
	}

	// Check all selection_* keys in the detection map
	for key, val := range detection {
		if !strings.HasPrefix(key, "selection") {
			continue
		}
		if matchSelectionValue(val, result.Value) {
			return true
		}
	}
	return false
}

// matchSelectionValue recursively checks if any string in a selection matches the result value.
func matchSelectionValue(sel interface{}, value string) bool {
	valueLower := strings.ToLower(value)

	switch v := sel.(type) {
	case string:
		return strings.Contains(valueLower, strings.ToLower(v))
	case []interface{}:
		for _, item := range v {
			if matchSelectionValue(item, value) {
				return true
			}
		}
	case map[string]interface{}:
		for _, mapVal := range v {
			if matchSelectionValue(mapVal, value) {
				return true
			}
		}
	}
	return false
}

// detectFromAllSigmaRules runs detection for all loaded SIGMA rules.
func (s *Scanner) detectFromAllSigmaRules() []DetectionResult {
	var results []DetectionResult
	for _, rule := range s.SigmaRules {
		softwareName := extractSoftwareNameFromTitle(rule.Title)
		if softwareName == "" {
			continue
		}
		ruleResults := s.detectFromSigmaRule(rule, softwareName)
		results = append(results, ruleResults...)
	}
	return results
}

// detectFromSigmaRule performs detection based on a specific SIGMA rule.
func (s *Scanner) detectFromSigmaRule(rule SigmaRule, softwareName string) []DetectionResult {
	var results []DetectionResult

	for key, val := range rule.Detection {
		if !strings.HasPrefix(key, "selection") {
			continue
		}

		// The selection value can be a list of maps (SIGMA standard format)
		switch sel := val.(type) {
		case []interface{}:
			for _, item := range sel {
				if m, ok := item.(map[string]interface{}); ok {
					results = append(results, s.processSelectionMap(softwareName, m)...)
				}
			}
		case map[string]interface{}:
			results = append(results, s.processSelectionMap(softwareName, sel)...)
		}
	}

	return results
}

// processSelectionMap processes a single selection map from a SIGMA rule.
func (s *Scanner) processSelectionMap(software string, sel map[string]interface{}) []DetectionResult {
	var results []DetectionResult

	for key, val := range sel {
		patterns := toStringSlice(val)
		if len(patterns) == 0 {
			continue
		}

		switch {
		case strings.HasPrefix(key, "Image|endswith"):
			results = append(results, s.detectProcessesByName(software, patterns)...)
		case strings.HasPrefix(key, "CommandLine|contains"):
			results = append(results, s.detectProcessesByCmdLine(software, patterns)...)
		case strings.HasPrefix(key, "ProcessName|contains"):
			results = append(results, s.detectProcessesByName(software, patterns)...)
		case strings.HasPrefix(key, "TargetFilename|contains"):
			results = append(results, s.detectFilesByPattern(software, patterns)...)
		case strings.HasPrefix(key, "EnvironmentVariables|contains"):
			results = append(results, s.detectEnvVars(software, patterns)...)
		case strings.HasPrefix(key, "QueryName"):
			// DNS detection - check if any of these domains resolve
			// (skip for now as DNS queries may be noisy)
		}
	}

	return results
}

// detectFilesByPattern checks for files/directories matching SIGMA path patterns.
func (s *Scanner) detectFilesByPattern(software string, patterns []string) []DetectionResult {
	var results []DetectionResult
	home := userHomeDir()

	for _, pattern := range patterns {
		// Convert SIGMA path patterns to OS-native paths
		var checkPaths []string

		if runtime.GOOS == "windows" {
			// Windows paths
			winPattern := strings.ReplaceAll(pattern, "/", "\\")
			if strings.HasPrefix(winPattern, "\\Users\\") {
				// Replace with actual user home
				checkPaths = append(checkPaths, filepath.Join(home, strings.TrimPrefix(winPattern, "\\Users\\")))
			} else if strings.HasPrefix(winPattern, "\\AppData\\") {
				checkPaths = append(checkPaths, filepath.Join(home, winPattern))
			} else if strings.HasPrefix(winPattern, "\\Program Files") {
				checkPaths = append(checkPaths, "C:"+winPattern)
			} else {
				checkPaths = append(checkPaths, filepath.Join(home, strings.TrimLeft(winPattern, "\\")))
			}
		} else {
			// Unix paths
			unixPattern := strings.ReplaceAll(pattern, "\\", "/")
			if strings.HasPrefix(unixPattern, "/.") || strings.HasPrefix(unixPattern, "/opt/") || strings.HasPrefix(unixPattern, "/usr/") || strings.HasPrefix(unixPattern, "/Library/") {
				if strings.HasPrefix(unixPattern, "/.") {
					checkPaths = append(checkPaths, filepath.Join(home, unixPattern))
				} else {
					checkPaths = append(checkPaths, unixPattern)
				}
			} else if strings.Contains(unixPattern, "/") {
				checkPaths = append(checkPaths, unixPattern)
				checkPaths = append(checkPaths, filepath.Join(home, strings.TrimLeft(unixPattern, "/")))
			}
		}

		for _, p := range checkPaths {
			p = strings.TrimRight(p, "/\\")
			if p != "" && pathExists(p) {
				results = append(results, DetectionResult{
					Software: software, DetectionType: "file_path",
					Value: p, Path: p, Confidence: "high",
				})
			}
		}
	}
	return results
}

// detectSoftwareFromRule detects software using custom rule format (file_paths, env vars, etc.).
func (s *Scanner) detectSoftwareFromRule(rule SigmaRule) []DetectionResult {
	var results []DetectionResult
	softwareName := getSoftwareNameFromRule(rule)

	detection := rule.Detection
	if detection == nil {
		return results
	}

	// File path detection from custom format
	if fpRaw, ok := detection["file_paths"]; ok {
		if fpMap, ok := fpRaw.(map[string]interface{}); ok {
			osKey := strings.ToLower(runtime.GOOS)
			if osKey == "darwin" {
				osKey = "macos"
			}
			if paths, ok := fpMap[osKey]; ok {
				for _, p := range toStringSlice(paths) {
					expanded := expandPath(p)
					if pathExists(expanded) {
						results = append(results, DetectionResult{
							Software: softwareName, DetectionType: "file_path",
							Value: expanded, Path: expanded, Confidence: "high",
						})
					}
				}
			}
		}
	}

	// Environment variables detection
	if evRaw, ok := detection["environment_variables"]; ok {
		for _, envVar := range toStringSlice(evRaw) {
			if val, exists := os.LookupEnv(envVar); exists {
				results = append(results, DetectionResult{
					Software: softwareName, DetectionType: "environment_variable",
					Value: fmt.Sprintf("%s=%s", envVar, val), Confidence: "high",
				})
			}
		}
	}

	// Process detection
	if pnRaw, ok := detection["process_names"]; ok {
		results = append(results, s.detectProcessesByName(softwareName, toStringSlice(pnRaw))...)
	}

	// Network port detection
	if npRaw, ok := detection["network_ports"]; ok {
		for _, portVal := range toIntSlice(npRaw) {
			if checkPortOpen(portVal) {
				results = append(results, DetectionResult{
					Software: softwareName, DetectionType: "network_port",
					Value: fmt.Sprintf("Port %d (HTTP API)", portVal), Confidence: "medium",
				})
			}
		}
	}

	// Windows registry detection
	if runtime.GOOS == "windows" {
		results = append(results, checkWindowsRegistryFromRule(softwareName)...)
	}

	return results
}

// extractSoftwareNameFromTitle maps a SIGMA rule title to a software name.
func extractSoftwareNameFromTitle(title string) string {
	titleLower := strings.ToLower(title)

	mapping := []struct {
		keyword string
		name    string
	}{
		{"cursor", "Cursor"},
		{"chatbox", "Chatbox"},
		{"github copilot", "GitHub Copilot"},
		{"replit ghostwriter", "Replit Ghostwriter"},
		{"windsurf", "Windsurf"},
		{"tabnine", "Tabnine"},
		{"zed", "Zed"},
		{"continue", "Continue"},
		{"chatgpt", "ChatGPT"},
		{"clawdbot", "ClawdBot"},
		{"openclaw", "OpenClaw"},
		{"moltbot", "MoltBot"},
		{"claude", "Claude"},
		{"google gemini", "Google Gemini"},
		{"brave leo", "Brave Leo"},
		{"poe", "Poe"},
		{"youchat", "YouChat"},
		{"you.com", "YouChat"},
		{"open webui", "Open WebUI"},
		{"anythingllm", "AnythingLLM"},
		{"librechat", "LibreChat"},
		{"jan", "Jan"},
		{"text generation webui", "Text Generation WebUI"},
		{"oobabooga", "Text Generation WebUI"},
		{"localai", "LocalAI"},
		{"llamafile", "Llamafile"},
		{"llama.cpp", "Llamafile"},
		{"faraday", "Faraday"},
		{"nvidia chat", "NVIDIA Chat with RTX"},
		{"rtx", "NVIDIA Chat with RTX"},
		{"ollama", "Ollama"},
		{"lm studio", "LM Studio"},
		{"gpt4all", "GPT4All"},
		{"vllm", "vLLM"},
	}

	for _, m := range mapping {
		if strings.Contains(titleLower, m.keyword) {
			return m.name
		}
	}
	return ""
}

// getSoftwareNameFromRule extracts the software name from a SIGMA rule.
func getSoftwareNameFromRule(rule SigmaRule) string {
	// Try title first
	if name := extractSoftwareNameFromTitle(rule.Title); name != "" {
		return name
	}

	// Try tags
	for _, tag := range rule.Tags {
		if strings.HasPrefix(tag, "llm.") || strings.HasPrefix(tag, "ai.") {
			parts := strings.SplitN(tag, ".", 2)
			if len(parts) == 2 {
				sw := parts[1]
				switch sw {
				case "ollama":
					return "Ollama"
				case "lmstudio":
					return "LM Studio"
				case "gpt4all":
					return "GPT4All"
				case "vllm":
					return "vLLM"
				case "clawdbot":
					return "ClawdBot"
				case "openclaw":
					return "OpenClaw"
				case "moltbot":
					return "MoltBot"
				}
			}
		}
	}

	return "Unknown Software"
}

// toStringSlice converts an interface{} to a []string.
func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return val
	case string:
		return []string{val}
	}
	return nil
}

// toIntSlice converts an interface{} to a []int.
func toIntSlice(v interface{}) []int {
	switch val := v.(type) {
	case []interface{}:
		var result []int
		for _, item := range val {
			switch n := item.(type) {
			case int:
				result = append(result, n)
			case float64:
				result = append(result, int(n))
			}
		}
		return result
	}
	return nil
}
