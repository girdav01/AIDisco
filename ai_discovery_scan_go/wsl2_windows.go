//go:build windows

package main

import (
	"fmt"
	"log"
	"strings"
)

// detectWSL2AI enumerates WSL2 distributions and checks for AI software inside them.
func (s *Scanner) detectWSL2AI() []DetectionResult {
	var results []DetectionResult

	// Get list of WSL distributions
	distros, err := listWSLDistros()
	if err != nil {
		if s.Verbose {
			log.Printf("WSL2 not available: %v", err)
		}
		return results
	}

	if len(distros) == 0 {
		return results
	}

	fmt.Printf("  Found %d WSL2 distribution(s)\n", len(distros))

	for _, distro := range distros {
		fmt.Printf("  Scanning WSL2 distro: %s (state: %s)\n", distro.Name, distro.State)

		// Only scan running distributions
		if !strings.EqualFold(distro.State, "running") {
			// Still report the distro exists
			results = append(results, DetectionResult{
				Software:      "WSL2 Distribution",
				DetectionType: "wsl2_distro",
				Value:         fmt.Sprintf("WSL2 distro: %s (state: %s, version: %s)", distro.Name, distro.State, distro.Version),
				Confidence:    "low",
			})
			continue
		}

		results = append(results, DetectionResult{
			Software:      "WSL2 Distribution",
			DetectionType: "wsl2_distro",
			Value:         fmt.Sprintf("WSL2 distro: %s (state: %s, version: %s)", distro.Name, distro.State, distro.Version),
			Confidence:    "medium",
		})

		// Check for AI software inside the running WSL distro
		results = append(results, s.scanWSLDistroForAI(distro.Name)...)
	}

	return results
}

// wslDistro holds information about a WSL distribution.
type wslDistro struct {
	Name    string
	State   string
	Version string
}

// listWSLDistros enumerates installed WSL distributions.
func listWSLDistros() ([]wslDistro, error) {
	out, err := runCommandTimeout("wsl", "--list", "--verbose")
	if err != nil {
		return nil, fmt.Errorf("wsl not available: %w", err)
	}

	var distros []wslDistro
	lines := strings.Split(strings.TrimSpace(out), "\n")

	for i, line := range lines {
		// Skip header line
		if i == 0 {
			continue
		}

		// Clean up the line (WSL output sometimes has weird Unicode chars)
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "*") // default distro marker
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Parse: NAME STATE VERSION
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		distros = append(distros, wslDistro{
			Name:    fields[0],
			State:   fields[1],
			Version: fields[2],
		})
	}

	return distros, nil
}

// scanWSLDistroForAI checks a running WSL2 distribution for AI software.
func (s *Scanner) scanWSLDistroForAI(distroName string) []DetectionResult {
	var results []DetectionResult

	// AI software binaries to check
	aiBinaries := []struct {
		binary   string
		software string
	}{
		{"ollama", "Ollama"},
		{"vllm", "vLLM"},
		{"litellm", "LiteLLM"},
		{"n8n", "n8n"},
		{"flowise", "FlowiseAI"},
		{"chainlit", "Chainlit"},
		{"streamlit", "Streamlit"},
		{"gradio", "Gradio"},
		{"jupyter", "Jupyter"},
		{"mlflow", "MLflow"},
		{"langchain-cli", "LangChain"},
		{"dify", "Dify"},
		{"localai", "LocalAI"},
		{"llamafile", "Llamafile"},
		{"llama-server", "Llamafile"},
		{"crewai", "CrewAI"},
	}

	for _, ai := range aiBinaries {
		out, err := runCommandTimeout("wsl", "-d", distroName, "--", "which", ai.binary)
		if err == nil && strings.TrimSpace(out) != "" {
			results = append(results, DetectionResult{
				Software:      ai.software,
				DetectionType: "wsl2_binary",
				Value:         fmt.Sprintf("WSL2 %s: %s found at %s", distroName, ai.software, strings.TrimSpace(out)),
				Path:          fmt.Sprintf("wsl://%s%s", distroName, strings.TrimSpace(out)),
				Confidence:    "high",
			})
		}
	}

	// Check for AI-related directories
	aiDirs := []struct {
		path     string
		software string
	}{
		{"~/.ollama", "Ollama"},
		{"~/.vllm", "vLLM"},
		{"~/.n8n", "n8n"},
		{"~/.cache/lm-studio", "LM Studio"},
		{"~/.local/share/gpt4all", "GPT4All"},
		{"~/.config/flowise", "FlowiseAI"},
		{"~/.langchain", "LangChain"},
		{"~/.dify", "Dify"},
	}

	for _, ai := range aiDirs {
		out, err := runCommandTimeout("wsl", "-d", distroName, "--", "test", "-d", ai.path, "&&", "echo", "exists")
		if err == nil && strings.Contains(out, "exists") {
			results = append(results, DetectionResult{
				Software:      ai.software,
				DetectionType: "wsl2_file_path",
				Value:         fmt.Sprintf("WSL2 %s: %s directory found at %s", distroName, ai.software, ai.path),
				Path:          fmt.Sprintf("wsl://%s/%s", distroName, ai.path),
				Confidence:    "high",
			})
		}
	}

	// Check for Docker inside WSL
	out, err := runCommandTimeout("wsl", "-d", distroName, "--", "docker", "ps", "--format", "{{.Image}}")
	if err == nil && strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			imageLower := strings.ToLower(strings.TrimSpace(line))
			if imageLower == "" {
				continue
			}
			for _, ai := range aiContainerImages {
				if strings.Contains(imageLower, strings.ToLower(ai.pattern)) {
					results = append(results, DetectionResult{
						Software:      ai.software,
						DetectionType: "wsl2_container",
						Value:         fmt.Sprintf("WSL2 %s: Docker container with %s image: %s", distroName, ai.software, line),
						Path:          fmt.Sprintf("wsl://%s/docker", distroName),
						Confidence:    "high",
					})
					break
				}
			}
		}
	}

	// Check for AI-related Python packages
	aiPyPackages := []struct {
		pkg      string
		software string
	}{
		{"openai", "AI API Provider"},
		{"anthropic", "AI API Provider"},
		{"langchain", "LangChain"},
		{"llama-index", "LlamaIndex"},
		{"transformers", "HuggingFace Transformers"},
		{"torch", "PyTorch"},
		{"tensorflow", "TensorFlow"},
		{"crewai", "CrewAI"},
		{"autogen", "AutoGen"},
		{"chromadb", "ChromaDB"},
		{"vllm", "vLLM"},
		{"litellm", "LiteLLM"},
	}

	pipOut, err := runCommandTimeout("wsl", "-d", distroName, "--", "pip", "list", "--format=columns")
	if err == nil {
		pipLower := strings.ToLower(pipOut)
		for _, pkg := range aiPyPackages {
			if strings.Contains(pipLower, pkg.pkg) {
				results = append(results, DetectionResult{
					Software:      pkg.software,
					DetectionType: "wsl2_python_package",
					Value:         fmt.Sprintf("WSL2 %s: Python package '%s' installed (%s)", distroName, pkg.pkg, pkg.software),
					Path:          fmt.Sprintf("wsl://%s/pip/%s", distroName, pkg.pkg),
					Confidence:    "medium",
				})
			}
		}
	}

	// Check for AI-related environment variables inside WSL
	aiEnvVars := []struct {
		pattern  string
		software string
	}{
		{"OPENAI_API_KEY", "AI API Provider"},
		{"ANTHROPIC_API_KEY", "AI API Provider"},
		{"OLLAMA_HOST", "Ollama"},
		{"LITELLM_", "LiteLLM"},
		{"N8N_", "n8n"},
		{"LANGCHAIN_", "LangChain"},
		{"HF_TOKEN", "HuggingFace"},
		{"HUGGINGFACE_", "HuggingFace"},
		{"GROQ_API_KEY", "AI API Provider"},
		{"MISTRAL_API_KEY", "AI API Provider"},
		{"CLAWDBOT_", "ClawdBot"},
		{"OPENCLAW_", "OpenClaw"},
	}

	envOut, err := runCommandTimeout("wsl", "-d", distroName, "--", "env")
	if err == nil {
		for _, line := range strings.Split(envOut, "\n") {
			lineUpper := strings.ToUpper(line)
			for _, ai := range aiEnvVars {
				if strings.Contains(lineUpper, ai.pattern) {
					results = append(results, DetectionResult{
						Software:      ai.software,
						DetectionType: "wsl2_env_var",
						Value:         fmt.Sprintf("WSL2 %s: %s", distroName, maskEnvValue(strings.TrimSpace(line))),
						Path:          fmt.Sprintf("wsl://%s/env", distroName),
						Confidence:    "high",
					})
					break
				}
			}
		}
	}

	return results
}
