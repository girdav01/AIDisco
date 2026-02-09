package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	// CLI flags matching the Python version
	output := flag.String("output", "ai_discovery_results.json", "Output file for results (JSON format)")
	verbose := flag.Bool("verbose", false, "Verbose output with detailed logging")
	sigmaDir := flag.String("sigma-dir", "sigma_rules", "Directory containing SIGMA rules")
	collectLogs := flag.Bool("collect-logs", false, "Collect logs from detected LLM software")
	logsOnly := flag.Bool("logs-only", false, "Only collect logs without running detection scan")
	maxFileSize := flag.Int("max-file-size", 100, "Maximum file size in MB to include in log collection (default: 100)")

	// Short flags
	flag.StringVar(output, "o", "ai_discovery_results.json", "Output file for results (shorthand)")
	flag.BoolVar(verbose, "v", false, "Verbose output (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `AI Discovery Scanner - Portable LLM Software Detection Tool (Go Version)
=========================================================================

A comprehensive security scanner for detecting Local Large Language Model
software installations. Compiles to a single static binary for Windows,
Linux, and macOS.

Usage:
  %s [flags]

Flags:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  %s                           # Basic scan
  %s -v                        # Verbose output
  %s --collect-logs            # Collect logs from detected software
  %s --logs-only               # Only collect logs without scanning
  %s --max-file-size 50        # Set 50MB file size limit
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	// Validate arguments
	if *maxFileSize <= 0 || *maxFileSize > 1000 {
		log.Fatal("Error: max-file-size must be between 1 and 1000 MB")
	}

	// Resolve sigma rules directory path relative to the executable if not absolute
	sigmaPath := *sigmaDir
	if !filepath.IsAbs(sigmaPath) {
		// Try relative to CWD first
		if _, err := os.Stat(sigmaPath); os.IsNotExist(err) {
			// Try relative to executable location
			execPath, err := os.Executable()
			if err == nil {
				candidate := filepath.Join(filepath.Dir(execPath), sigmaPath)
				if _, err := os.Stat(candidate); err == nil {
					sigmaPath = candidate
				}
			}
		}
	}

	// Initialise scanner
	scanner, err := NewScanner(sigmaPath, *maxFileSize, *verbose)
	if err != nil {
		log.Fatalf("Error: failed to initialise scanner: %v", err)
	}

	// Logs-only mode
	if *logsOnly {
		fmt.Println("Collecting logs from LLM software installations...")
		archivePath, err := scanner.CollectLogs()
		if err != nil {
			log.Fatalf("Error: log collection failed: %v", err)
		}
		fmt.Printf("Log archive created: %s\n", archivePath)
		return
	}

	// Run scan
	results := scanner.RunScan()

	// Generate and print summary
	summary := GenerateHumanReadableSummary(results)
	fmt.Println(summary)

	// Save JSON results
	var savedFile string
	if *output == "ai_discovery_results.json" {
		savedFile, err = scanner.SaveResults(results, "")
	} else {
		savedFile, err = scanner.SaveResults(results, *output)
	}
	if err != nil {
		log.Fatalf("Error: could not save results: %v", err)
	}
	fmt.Printf("Results saved to: %s\n", savedFile)

	// Save human-readable summary
	summaryPath, err := scanner.SaveSummary(summary, savedFile)
	if err != nil {
		log.Printf("Warning: could not save summary: %v", err)
	} else {
		fmt.Printf("Human-readable summary saved to: %s\n", summaryPath)
	}

	// Collect logs if requested
	if *collectLogs {
		if results.Summary.TotalDetections > 0 {
			fmt.Println("\n" + "==================================================")
			archivePath, err := scanner.CollectLogs()
			if err != nil {
				log.Printf("Error: log collection failed: %v", err)
			} else {
				fmt.Printf("Log archive created: %s\n", archivePath)
			}
		} else {
			fmt.Println("\nNo LLM software detected. Skipping log collection.")
		}
	}
}
