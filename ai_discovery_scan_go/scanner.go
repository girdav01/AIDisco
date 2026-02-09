package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Scanner is the main LLM software detector.
type Scanner struct {
	SigmaRulesDir    string
	MaxFileSizeMB    int
	Verbose          bool
	SigmaRules       []SigmaRule
	FileVersionCache map[string]string
}

// NewScanner creates and initialises a new Scanner.
func NewScanner(sigmaDir string, maxFileSizeMB int, verbose bool) (*Scanner, error) {
	if maxFileSizeMB <= 0 {
		return nil, fmt.Errorf("max_file_size_mb must be a positive integer")
	}
	s := &Scanner{
		SigmaRulesDir:    sigmaDir,
		MaxFileSizeMB:    maxFileSizeMB,
		Verbose:          verbose,
		FileVersionCache: make(map[string]string),
	}
	if err := s.loadSigmaRules(); err != nil {
		log.Printf("Warning: could not load SIGMA rules: %v", err)
	}
	return s, nil
}

// RunScan performs the full detection scan and returns the results.
func (s *Scanner) RunScan() *ScanResults {
	fmt.Println("Starting LLM Software Detection Scan...")
	fmt.Printf("Operating System: %s %s\n", runtime.GOOS, osRelease())
	fmt.Printf("Architecture: %s\n", runtime.GOARCH)
	fmt.Println(strings.Repeat("-", 50))

	var allResults []DetectionResult

	// Legacy hardcoded detection methods
	fmt.Println("Running legacy detection methods...")
	allResults = append(allResults, s.detectOllama()...)
	allResults = append(allResults, s.detectLMStudio()...)
	allResults = append(allResults, s.detectGPT4All()...)
	allResults = append(allResults, s.detectVLLM()...)

	// SIGMA rule-based detection
	fmt.Println("Running SIGMA rule-based detection...")
	allResults = append(allResults, s.detectFromAllSigmaRules()...)

	// De-duplicate results from overlapping detection methods
	fmt.Println("De-duplicating detection results...")
	allResults = deduplicateResults(allResults)

	// Apply SIGMA rules for matching
	sigmaMatches := s.applySigmaRules(allResults)

	// Build software summary
	softwareSummary := make(map[string]SoftwareSummary)
	for _, r := range allResults {
		summary, exists := softwareSummary[r.Software]
		if !exists {
			summary = SoftwareSummary{
				SanctionStatus: getSanctionStatus(r.Software),
			}
		}
		summary.DetectionCount++
		// Track unique detection types
		found := false
		for _, dt := range summary.DetectionTypes {
			if dt == r.DetectionType {
				found = true
				break
			}
		}
		if !found {
			summary.DetectionTypes = append(summary.DetectionTypes, r.DetectionType)
		}
		softwareSummary[r.Software] = summary
	}

	// Build detections output
	detections := make([]DetectionOutput, 0, len(allResults))
	for _, r := range allResults {
		detections = append(detections, DetectionOutput{
			Software:       r.Software,
			DetectionType:  r.DetectionType,
			Value:          r.Value,
			Path:           r.Path,
			Confidence:     r.Confidence,
			SanctionStatus: getSanctionStatus(r.Software),
			Version:        nil,
		})
	}

	high, medium := 0, 0
	for _, r := range allResults {
		switch r.Confidence {
		case "high":
			high++
		case "medium":
			medium++
		}
	}

	return &ScanResults{
		ScanTimestamp: time.Now().Format(time.RFC3339),
		SystemInfo:    getSystemInfo(),
		Detections:    detections,
		SigmaMatches:  sigmaMatches,
		SoftwareFound: softwareSummary,
		Summary: ScanSummary{
			TotalDetections:     len(allResults),
			UniqueSoftwareCount: len(softwareSummary),
			HighConfidence:      high,
			MediumConfidence:    medium,
		},
	}
}

// checkPortOpen tests whether a TCP port is open on localhost.
func checkPortOpen(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	addr := fmt.Sprintf("localhost:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// getSystemInfo gathers system information.
func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	return SystemInfo{
		ComputerName: hostname,
		OS:           runtime.GOOS,
		Release:      osRelease(),
		Architecture: runtime.GOARCH,
		GoVersion:    runtime.Version(),
		IPAddresses:  getSystemIPAddresses(),
	}
}

// getSystemIPAddresses returns a map of interface names to their IPv4 addresses.
func getSystemIPAddresses() map[string][]string {
	result := make(map[string][]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		result["error"] = []string{fmt.Sprintf("Failed to get interfaces: %v", err)}
		return result
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ipv4s []string
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				ipv4s = append(ipv4s, ipNet.IP.String())
			}
		}
		if len(ipv4s) > 0 {
			result[iface.Name] = ipv4s
		}
	}
	return result
}

// getSanctionStatus returns whether a software is sanctioned.
func getSanctionStatus(name string) string {
	sanctioned := []string{"Ollama", "LM Studio", "GPT4All", "vLLM", "GitHub Copilot", "Cursor", "Chatbox"}
	unsanctioned := []string{
		"Replit Ghostwriter", "Windsurf", "Tabnine", "Zed", "Continue", "ChatGPT",
		"Claude", "ClawdBot", "Google Gemini", "Brave Leo", "Poe", "YouChat",
		"Open WebUI", "AnythingLLM", "LibreChat", "Jan", "Text Generation WebUI",
		"LocalAI", "Llamafile", "Faraday", "NVIDIA Chat with RTX",
	}

	lower := strings.ToLower(name)
	for _, s := range sanctioned {
		if strings.Contains(lower, strings.ToLower(s)) {
			return "sanctioned"
		}
	}
	for _, s := range unsanctioned {
		if strings.Contains(lower, strings.ToLower(s)) {
			return "unsanctioned"
		}
	}
	return "unknown"
}

// osRelease returns a short string describing the OS release.
func osRelease() string {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				}
			}
		}
		return "Linux"
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	default:
		return runtime.GOOS
	}
}

// userHomeDir returns the user's home directory.
func userHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// expandPath expands ~ to the user home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") || path == "~" {
		home := userHomeDir()
		if home != "" {
			return filepath.Join(home, path[2:])
		}
	}
	return os.ExpandEnv(path)
}

// pathExists checks whether a path exists on disk.
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// deduplicateResults removes duplicate detections caused by overlapping rules.
//
// When both legacy (hardcoded) detection and SIGMA rule-based detection find the
// same artifact, or when generic AI API provider rules overlap with specific
// software rules, this function consolidates duplicates.
//
// Strategy:
//  1. Group results by (detection_type, value) — same evidence once.
//  2. Keep the result with the highest confidence.
//  3. On tie, prefer the more specific (non-generic) software name.
func deduplicateResults(results []DetectionResult) []DetectionResult {
	if len(results) == 0 {
		return results
	}

	genericNames := map[string]bool{
		"openai api": true, "anthropic api": true, "google ai api": true,
		"mistral api": true, "groq api": true, "cohere api": true,
		"ai api provider": true, "ai proxy": true, "ai framework": true,
		"ai sdk": true, "unknown software": true,
	}

	confidenceRank := map[string]int{"high": 3, "medium": 2, "low": 1}

	type dedupKey struct {
		detectionType string
		value         string
	}

	seen := make(map[dedupKey]DetectionResult)

	for _, r := range results {
		key := dedupKey{r.DetectionType, r.Value}
		existing, exists := seen[key]
		if !exists {
			seen[key] = r
			continue
		}

		newRank := confidenceRank[r.Confidence]
		oldRank := confidenceRank[existing.Confidence]

		if newRank > oldRank {
			seen[key] = r
		} else if newRank == oldRank {
			existingGeneric := genericNames[strings.ToLower(existing.Software)]
			newGeneric := genericNames[strings.ToLower(r.Software)]

			if existingGeneric && !newGeneric {
				seen[key] = r
			} else if !existingGeneric && !newGeneric {
				if len(r.Software) > len(existing.Software) {
					seen[key] = r
				}
			}
		}
	}

	deduped := make([]DetectionResult, 0, len(seen))
	for _, r := range seen {
		deduped = append(deduped, r)
	}

	removed := len(results) - len(deduped)
	if removed > 0 {
		log.Printf("De-duplication removed %d duplicate detections (%d -> %d)",
			removed, len(results), len(deduped))
	}

	return deduped
}
