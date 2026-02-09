package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// SaveResults writes scan results as JSON.
func (s *Scanner) SaveResults(results *ScanResults, filename string) (string, error) {
	outputDir := "output"
	os.MkdirAll(outputDir, 0o755)

	if filename == "" {
		timestamp := time.Now().Format("20060102_150405")
		hostname, _ := os.Hostname()
		hostname = strings.ReplaceAll(strings.ReplaceAll(hostname, " ", "_"), "-", "_")
		filename = fmt.Sprintf("ai_discovery_results_%s_%s.json", hostname, timestamp)
	} else {
		filename = validateFilename(filename)
	}

	if !strings.HasSuffix(filename, ".json") {
		filename += ".json"
	}

	outPath := filepath.Join(outputDir, filename)

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("failed to write results: %w", err)
	}

	return outPath, nil
}

// SaveSummary writes the human-readable summary to a text file.
func (s *Scanner) SaveSummary(summary, jsonPath string) (string, error) {
	outputDir := "output"
	os.MkdirAll(outputDir, 0o755)

	base := filepath.Base(jsonPath)
	txtName := strings.TrimSuffix(base, ".json") + "_summary.txt"
	outPath := filepath.Join(outputDir, txtName)

	if err := os.WriteFile(outPath, []byte(summary), 0o644); err != nil {
		return "", fmt.Errorf("failed to write summary: %w", err)
	}
	return outPath, nil
}

// GenerateHumanReadableSummary creates a formatted text report.
func GenerateHumanReadableSummary(results *ScanResults) string {
	var b strings.Builder

	line := strings.Repeat("=", 80)
	dash := strings.Repeat("-", 40)

	b.WriteString(line + "\n")
	b.WriteString("LLM SOFTWARE DETECTION SCAN REPORT\n")
	b.WriteString(line + "\n")
	b.WriteString(fmt.Sprintf("Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	hostname, _ := os.Hostname()
	b.WriteString(fmt.Sprintf("Machine Name: %s\n", hostname))
	b.WriteString(fmt.Sprintf("Operating System: %s %s\n", runtime.GOOS, osRelease()))
	b.WriteString("\n")

	b.WriteString("SCAN SUMMARY:\n")
	b.WriteString(dash + "\n")
	b.WriteString(fmt.Sprintf("Total Detections: %d\n", results.Summary.TotalDetections))
	b.WriteString(fmt.Sprintf("Unique Software Count: %d\n", results.Summary.UniqueSoftwareCount))
	b.WriteString(fmt.Sprintf("High Confidence Detections: %d\n", results.Summary.HighConfidence))
	b.WriteString(fmt.Sprintf("Medium Confidence Detections: %d\n", results.Summary.MediumConfidence))
	b.WriteString("\n")

	if len(results.Detections) > 0 {
		b.WriteString("APPLICATIONS DETECTED:\n")
		b.WriteString(dash + "\n")

		grouped := make(map[string][]DetectionOutput)
		for _, d := range results.Detections {
			grouped[d.Software] = append(grouped[d.Software], d)
		}

		for software, detections := range grouped {
			info, ok := results.SoftwareFound[software]
			sanctionFlag := "N"
			if ok && info.SanctionStatus == "sanctioned" {
				sanctionFlag = "Y"
			}

			b.WriteString(fmt.Sprintf("* %s\n", strings.ToUpper(software)))
			b.WriteString(fmt.Sprintf("  - Detection Count: %d\n", len(detections)))
			b.WriteString(fmt.Sprintf("  - Sanctioned: %s\n", sanctionFlag))
			if ok && info.Version != nil {
				b.WriteString(fmt.Sprintf("  - Version: %s\n", *info.Version))
			} else {
				b.WriteString("  - Version: Not available\n")
			}
			b.WriteString("  - Detections:\n")
			for _, d := range detections {
				b.WriteString(fmt.Sprintf("    * Type: %s\n", d.DetectionType))
				b.WriteString(fmt.Sprintf("      Value: %s\n", d.Value))
				b.WriteString(fmt.Sprintf("      Confidence: %s\n", d.Confidence))
			}
			b.WriteString("\n")
		}
	}

	if len(results.SigmaMatches) > 0 {
		b.WriteString("SIGMA RULE MATCHES:\n")
		b.WriteString(dash + "\n")
		for _, m := range results.SigmaMatches {
			b.WriteString(fmt.Sprintf("* %s\n", m.RuleTitle))
			b.WriteString(fmt.Sprintf("  - Level: %s\n", m.Level))
			b.WriteString("\n")
		}
	}

	b.WriteString("RECOMMENDATIONS:\n")
	b.WriteString(dash + "\n")
	if len(results.SoftwareFound) > 0 {
		b.WriteString("* LLM software detected on this system\n")
		b.WriteString("* Review security policies for LLM software usage\n")
		b.WriteString("* Consider implementing access controls and monitoring\n")
		b.WriteString("* Verify software versions for known vulnerabilities\n")
		b.WriteString("* Review collected logs for suspicious activity\n")
	} else {
		b.WriteString("* No LLM software detected on this system\n")
		b.WriteString("* System appears to be free of LLM software installations\n")
	}

	b.WriteString("\n")
	b.WriteString(line + "\n")
	b.WriteString("End of Report\n")
	b.WriteString(line + "\n")

	return b.String()
}
