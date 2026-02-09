package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CollectLogs gathers logs from detected LLM software and creates a ZIP archive.
func (s *Scanner) CollectLogs() (string, error) {
	fmt.Println("Collecting LLM software logs...")

	tempDir := "llm_logs_temp"
	os.RemoveAll(tempDir)
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	var collectedFiles []string

	// Collect logs for each software type using legacy paths
	collectedFiles = append(collectedFiles, s.collectSoftwareLogs(tempDir, "ollama", ollamaLogPaths())...)
	collectedFiles = append(collectedFiles, s.collectSoftwareLogs(tempDir, "lmstudio", lmstudioLogPaths())...)
	collectedFiles = append(collectedFiles, s.collectSoftwareLogs(tempDir, "gpt4all", gpt4allLogPaths())...)
	collectedFiles = append(collectedFiles, s.collectSoftwareLogs(tempDir, "vllm", vllmLogPaths())...)

	// Collect process info and env vars for each detected software
	procs := getRunningProcesses()
	for _, sw := range []string{"ollama", "lmstudio", "gpt4all", "vllm"} {
		swDir := filepath.Join(tempDir, sw)
		os.MkdirAll(swDir, 0o755)
		collectedFiles = append(collectedFiles, collectProcessInfo(sw, swDir, procs)...)
		collectedFiles = append(collectedFiles, collectEnvVars(sw, swDir)...)
	}

	// Create output directory
	outputDir := "output"
	os.MkdirAll(outputDir, 0o755)

	timestamp := time.Now().Format("20060102_150405")
	archivePath := filepath.Join(outputDir, fmt.Sprintf("ai_discovery_logs_%s.zip", timestamp))

	if err := createZipArchive(tempDir, archivePath); err != nil {
		return "", fmt.Errorf("failed to create archive: %w", err)
	}

	fmt.Printf("Log collection complete. Archive created: %s\n", archivePath)
	fmt.Printf("Total files collected: %d\n", len(collectedFiles))
	return archivePath, nil
}

// collectSoftwareLogs collects log files for a specific software.
func (s *Scanner) collectSoftwareLogs(tempDir, software string, logPaths []string) []string {
	var collected []string
	swDir := filepath.Join(tempDir, software)
	os.MkdirAll(swDir, 0o755)

	for _, basePath := range logPaths {
		if !pathExists(basePath) {
			continue
		}
		fi, err := os.Stat(basePath)
		if err != nil {
			continue
		}

		destName := filepath.Base(basePath)
		destPath := filepath.Join(swDir, destName)

		if fi.IsDir() {
			collected = append(collected, copyDirectoryFiltered(basePath, destPath, software, s.MaxFileSizeMB)...)
		} else {
			if shouldIncludeFile(basePath, s.MaxFileSizeMB) {
				if err := copyFile(basePath, destPath); err == nil {
					collected = append(collected, filepath.Join(software, destName))
				}
			}
		}
	}
	return collected
}

// shouldIncludeFile determines whether a file should be included in log collection.
func shouldIncludeFile(path string, maxSizeMB int) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}

	maxSize := int64(maxSizeMB) * 1024 * 1024
	if fi.Size() > maxSize {
		return false
	}

	if !isTextFile(path) {
		return false
	}
	if isBinaryFile(path) {
		return false
	}

	// Check for model-related filenames
	nameLower := strings.ToLower(filepath.Base(path))
	modelKeywords := []string{"model", "weights", "checkpoint", "tensor", "gguf", "ggml", "safetensors"}
	for _, kw := range modelKeywords {
		if strings.Contains(nameLower, kw) && fi.Size() > 10*1024*1024 {
			return false
		}
	}

	// Quick binary detection: read first 1KB and check for null bytes
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	buf = buf[:n]

	for _, b := range buf {
		if b == 0 {
			return false
		}
	}

	// Check binary signatures
	sigs := [][]byte{
		{0x4D, 0x5A},             // MZ (Windows exe)
		{0x7F, 0x45, 0x4C, 0x46}, // ELF
		{0xFE, 0xED, 0xFA},       // Mach-O
		{0x50, 0x4B},             // PK (ZIP)
		{0x1F, 0x8B},             // GZIP
		{0x89, 0x50, 0x4E, 0x47}, // PNG
		{0xFF, 0xD8, 0xFF},       // JPEG
		{0x25, 0x50, 0x44, 0x46}, // %PDF
	}
	for _, sig := range sigs {
		if len(buf) >= len(sig) {
			match := true
			for i, b := range sig {
				if buf[i] != b {
					match = false
					break
				}
			}
			if match {
				return false
			}
		}
	}

	return true
}

// copyDirectoryFiltered recursively copies text files from a directory.
func copyDirectoryFiltered(srcDir, destDir, software string, maxSizeMB int) []string {
	var collected []string
	os.MkdirAll(destDir, 0o755)

	filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors
		}
		relPath, _ := filepath.Rel(srcDir, path)

		if d.IsDir() {
			os.MkdirAll(filepath.Join(destDir, relPath), 0o755)
			return nil
		}

		destFile := filepath.Join(destDir, relPath)
		if shouldIncludeFile(path, maxSizeMB) {
			if err := copyFile(path, destFile); err == nil {
				collected = append(collected, filepath.Join(software, relPath))
			}
		} else {
			// Create a placeholder
			placeholder := destFile + ".skipped"
			content := fmt.Sprintf("File skipped during log collection: %s\nOriginal path: %s\nReason: Binary or large file\n", d.Name(), path)
			os.WriteFile(placeholder, []byte(content), 0o644)
			collected = append(collected, filepath.Join(software, relPath+".skipped"))
		}
		return nil
	})

	return collected
}

// copyFile copies a single file from src to dst.
func copyFile(src, dst string) error {
	os.MkdirAll(filepath.Dir(dst), 0o755)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// createZipArchive creates a ZIP archive of all files in sourceDir.
func createZipArchive(sourceDir, archivePath string) error {
	os.MkdirAll(filepath.Dir(archivePath), 0o755)
	zipFile, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	w := zip.NewWriter(zipFile)
	defer w.Close()

	return filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		relPath, _ := filepath.Rel(sourceDir, path)

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		zw, err := w.Create(relPath)
		if err != nil {
			return nil
		}
		_, _ = io.Copy(zw, f)
		return nil
	})
}

// collectProcessInfo writes running process info for a software to a JSON file.
func collectProcessInfo(software, targetDir string, allProcs []ProcessInfo) []string {
	var matched []ProcessInfo
	for _, p := range allProcs {
		if strings.Contains(strings.ToLower(p.Name), strings.ToLower(software)) {
			matched = append(matched, p)
		}
	}
	if len(matched) == 0 {
		return nil
	}

	data, err := json.MarshalIndent(matched, "", "  ")
	if err != nil {
		return nil
	}
	filename := fmt.Sprintf("%s_processes.json", software)
	outPath := filepath.Join(targetDir, filename)
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return nil
	}
	return []string{filepath.Join(software, filename)}
}

// collectEnvVars writes matching environment variables to a JSON file.
func collectEnvVars(software, targetDir string) []string {
	envVars := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.Contains(strings.ToLower(parts[0]), strings.ToLower(software)) ||
			strings.Contains(strings.ToLower(parts[1]), strings.ToLower(software)) {
			envVars[parts[0]] = parts[1]
		}
	}
	if len(envVars) == 0 {
		return nil
	}

	data, err := json.MarshalIndent(envVars, "", "  ")
	if err != nil {
		return nil
	}
	filename := fmt.Sprintf("%s_environment.json", software)
	outPath := filepath.Join(targetDir, filename)
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return nil
	}
	return []string{filepath.Join(software, filename)}
}

// ---------------------------------------------------------------------------
// Log path definitions per software and OS
// ---------------------------------------------------------------------------

func ollamaLogPaths() []string {
	home := userHomeDir()
	switch runtime.GOOS {
	case "windows":
		return []string{
			filepath.Join(home, ".ollama"),
			filepath.Join(home, "AppData", "Local", "Programs", "Ollama"),
			filepath.Join(home, "AppData", "Roaming", "Ollama"),
			`C:\Program Files\Ollama`,
		}
	case "darwin":
		return []string{
			"/Applications/Ollama.app",
			filepath.Join(home, ".ollama"),
			filepath.Join(home, "Library", "Logs", "Ollama"),
			filepath.Join(home, "Library", "Application Support", "Ollama"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".ollama"),
			"/var/log/ollama",
			"/var/lib/ollama",
		}
	}
	return nil
}

func lmstudioLogPaths() []string {
	home := userHomeDir()
	switch runtime.GOOS {
	case "windows":
		return []string{
			filepath.Join(home, "AppData", "Local", "LMStudio"),
			filepath.Join(home, "AppData", "Roaming", "LMStudio"),
			filepath.Join(home, ".cache", "lm-studio"),
			filepath.Join(home, ".lmstudio"),
		}
	case "darwin":
		return []string{
			filepath.Join(home, ".cache", "lm-studio"),
			filepath.Join(home, ".lmstudio"),
			filepath.Join(home, "Library", "Application Support", "LMStudio"),
			filepath.Join(home, "Library", "Logs", "LMStudio"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".cache", "lm-studio"),
			filepath.Join(home, ".lmstudio"),
		}
	}
	return nil
}

func gpt4allLogPaths() []string {
	home := userHomeDir()
	switch runtime.GOOS {
	case "windows":
		return []string{
			filepath.Join(home, "AppData", "Local", "GPT4All"),
			filepath.Join(home, "AppData", "Roaming", "GPT4All"),
			filepath.Join(home, ".gpt4all"),
		}
	case "darwin":
		return []string{
			filepath.Join(home, ".gpt4all"),
			filepath.Join(home, "Library", "Application Support", "GPT4All"),
			filepath.Join(home, "Library", "Logs", "GPT4All"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".gpt4all"),
			filepath.Join(home, ".local", "share", "gpt4all"),
		}
	}
	return nil
}

func vllmLogPaths() []string {
	home := userHomeDir()
	switch runtime.GOOS {
	case "windows":
		return []string{
			filepath.Join(home, ".vllm"),
			filepath.Join(home, "vllm"),
		}
	case "darwin":
		return []string{
			filepath.Join(home, ".vllm"),
			filepath.Join(home, "vllm"),
			filepath.Join(home, "Library", "Application Support", "vLLM"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".vllm"),
			filepath.Join(home, "vllm"),
			"/var/log/vllm",
		}
	}
	return nil
}

// collectVersionInfo attempts to get version information for detected software.
func (s *Scanner) collectVersionInfo(software, targetDir string) []string {
	versionInfo := map[string]interface{}{
		"software":             software,
		"collection_timestamp": time.Now().Format(time.RFC3339),
		"version_sources":      map[string]interface{}{},
	}

	// Try running <software> --version
	output := tryRunVersion(software)
	if output != "" {
		sources := versionInfo["version_sources"].(map[string]interface{})
		sources["command_line"] = map[string]string{
			"command": software + " --version",
			"output":  output,
			"version": output,
		}
	}

	sources := versionInfo["version_sources"].(map[string]interface{})
	if len(sources) == 0 {
		return nil
	}

	data, err := json.MarshalIndent(versionInfo, "", "  ")
	if err != nil {
		return nil
	}
	filename := fmt.Sprintf("%s_version.json", software)
	outPath := filepath.Join(targetDir, filename)
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		log.Printf("Warning: could not write version info for %s: %v", software, err)
		return nil
	}
	return []string{filepath.Join(software, filename)}
}

// tryRunVersion attempts to run "<binary> --version" and returns the output.
func tryRunVersion(binary string) string {
	out, err := runCommandTimeout(binary, "--version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
