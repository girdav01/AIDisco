package main

// DetectionResult represents a single detection finding.
type DetectionResult struct {
	Software      string `json:"software"`
	DetectionType string `json:"detection_type"`
	Value         string `json:"value"`
	Path          string `json:"path,omitempty"`
	Confidence    string `json:"confidence"`
}

// ScanResults is the top-level output of a scan.
type ScanResults struct {
	ScanTimestamp string                     `json:"scan_timestamp"`
	SystemInfo    SystemInfo                 `json:"system_info"`
	Detections    []DetectionOutput          `json:"detections"`
	SigmaMatches  []SigmaMatch              `json:"sigma_matches"`
	SoftwareFound map[string]SoftwareSummary `json:"software_found"`
	Summary       ScanSummary                `json:"summary"`
}

// SystemInfo holds information about the scanned system.
type SystemInfo struct {
	ComputerName string              `json:"computer_name"`
	OS           string              `json:"os"`
	Release      string              `json:"release"`
	Architecture string              `json:"architecture"`
	GoVersion    string              `json:"go_version"`
	IPAddresses  map[string][]string `json:"ip_addresses"`
}

// DetectionOutput is one detection in the JSON output.
type DetectionOutput struct {
	Software       string  `json:"software"`
	DetectionType  string  `json:"detection_type"`
	Value          string  `json:"value"`
	Path           string  `json:"path,omitempty"`
	Confidence     string  `json:"confidence"`
	SanctionStatus string  `json:"sanction_status"`
	Version        *string `json:"version"`
}

// SoftwareSummary summarises detections for one software product.
type SoftwareSummary struct {
	DetectionCount int      `json:"detection_count"`
	SanctionStatus string   `json:"sanction_status"`
	Version        *string  `json:"version,omitempty"`
	DetectionTypes []string `json:"detection_types"`
}

// SigmaMatch records a SIGMA rule that matched a detection.
type SigmaMatch struct {
	RuleID    string         `json:"rule_id"`
	RuleTitle string         `json:"rule_title"`
	Detection SigmaDetection `json:"detection"`
	Level     string         `json:"level"`
}

// SigmaDetection is the detection detail inside a SigmaMatch.
type SigmaDetection struct {
	Software string `json:"software"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

// ScanSummary holds aggregate scan stats.
type ScanSummary struct {
	TotalDetections     int `json:"total_detections"`
	UniqueSoftwareCount int `json:"unique_software_count"`
	HighConfidence      int `json:"high_confidence"`
	MediumConfidence    int `json:"medium_confidence"`
}

// SigmaRule represents a parsed SIGMA rule YAML file.
type SigmaRule struct {
	Title       string                 `yaml:"title" json:"title"`
	ID          string                 `yaml:"id" json:"id"`
	Status      string                 `yaml:"status" json:"status"`
	Description string                 `yaml:"description" json:"description"`
	Author      string                 `yaml:"author" json:"author"`
	Date        string                 `yaml:"date" json:"date"`
	Modified    string                 `yaml:"modified" json:"modified"`
	Tags        []string               `yaml:"tags" json:"tags"`
	LogSource   map[string]string      `yaml:"logsource" json:"logsource"`
	Detection   map[string]interface{} `yaml:"detection" json:"detection"`
	Fields      []string               `yaml:"fields" json:"fields"`
	FalsePos    []string               `yaml:"falsepositives" json:"falsepositives"`
	Level       string                 `yaml:"level" json:"level"`
}

// ProcessInfo holds information about a running process.
type ProcessInfo struct {
	PID     int
	Name    string
	Exe     string
	CmdLine string
}
