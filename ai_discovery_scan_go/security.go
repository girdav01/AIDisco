package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxPathLength = 4096
	maxFileSize   = 100 * 1024 * 1024 // 100 MB
)

var (
	allowedExtensions = map[string]bool{
		".txt": true, ".log": true, ".json": true, ".yml": true, ".yaml": true,
		".conf": true, ".config": true, ".ini": true,
	}
	binaryExtensions = map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true,
		".safetensors": true, ".gguf": true, ".ggml": true, ".model": true,
		".weights": true, ".pth": true, ".pt": true, ".ckpt": true, ".h5": true,
		".pb": true, ".onnx": true, ".pkl": true, ".pickle": true, ".joblib": true,
		".npy": true, ".npz": true, ".parquet": true, ".feather": true,
		".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".7z": true,
		".rar": true, ".iso": true, ".img": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".tiff": true, ".ico": true, ".svg": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true,
		".flac": true, ".ogg": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".ppt": true, ".pptx": true,
	}
	textExtensions = map[string]bool{
		".txt": true, ".log": true, ".json": true, ".yml": true, ".yaml": true,
		".xml": true, ".csv": true, ".md": true, ".ini": true, ".cfg": true,
		".conf": true, ".config": true, ".properties": true, ".env": true,
		".bat": true, ".sh": true, ".ps1": true, ".py": true, ".js": true,
		".html": true, ".css": true, ".sql": true, ".sqlite": true, ".db": true,
		".sqlite3": true,
	}
)

// sanitizePath validates a path to prevent path traversal attacks.
func sanitizePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path must not be empty")
	}

	normalized := filepath.Clean(path)

	dangerousPatterns := []string{".." + string(os.PathSeparator), string(os.PathSeparator) + ".."}
	for _, p := range dangerousPatterns {
		if strings.Contains(normalized, p) {
			return "", fmt.Errorf("path traversal attempt detected: %s", path)
		}
	}

	parts := strings.Split(normalized, string(os.PathSeparator))
	for _, part := range parts {
		if part == ".." || strings.HasPrefix(part, "..") {
			return "", fmt.Errorf("directory traversal attempt detected: %s", part)
		}
	}

	if len(normalized) > maxPathLength {
		return "", fmt.Errorf("path too long: %d characters", len(normalized))
	}

	return normalized, nil
}

// validateFilename sanitises a filename by replacing dangerous characters.
func validateFilename(filename string) string {
	dangerous := []string{"<", ">", ":", "\"", "|", "?", "*", "\\", "/"}
	for _, ch := range dangerous {
		filename = strings.ReplaceAll(filename, ch, "_")
	}

	reserved := map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true,
		"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
		"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}

	ext := filepath.Ext(filename)
	nameOnly := strings.TrimSuffix(filename, ext)
	if reserved[strings.ToUpper(nameOnly)] {
		filename = "_" + filename
	}
	return filename
}

// isSafeExtension returns true if the file extension is considered safe for processing.
func isSafeExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return allowedExtensions[ext]
}

// isTextFile returns true if the file extension belongs to a known text format.
func isTextFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return textExtensions[ext]
}

// isBinaryFile returns true if the file extension belongs to a known binary format.
func isBinaryFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return binaryExtensions[ext]
}
