package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// Known AI-related container image patterns.
// Maps pattern fragment -> software name.
var aiContainerImages = []struct {
	pattern  string
	software string
}{
	// LLM inference servers
	{"ollama/ollama", "Ollama"},
	{"vllm/vllm", "vLLM"},
	{"huggingface/text-generation-inference", "HuggingFace TGI"},
	{"localai/localai", "LocalAI"},
	{"go-skynet/local-ai", "LocalAI"},
	// AI chat/UI platforms
	{"open-webui/open-webui", "Open WebUI"},
	{"mintplexlabs/anythingllm", "AnythingLLM"},
	{"danny-avila/librechat", "LibreChat"},
	{"librechat/librechat", "LibreChat"},
	{"jan-ai/jan", "Jan"},
	{"text-generation-webui", "Text Generation WebUI"},
	// AI workflow/orchestration
	{"langgenius/dify", "Dify"},
	{"flowiseai/flowise", "FlowiseAI"},
	{"n8nio/n8n", "n8n"},
	{"docker.n8n.io/n8nio/n8n", "n8n"},
	{"chainlit/chainlit", "Chainlit"},
	{"gradio/gradio", "Gradio"},
	// AI proxy/gateway
	{"berriai/litellm", "LiteLLM"},
	{"litellm/litellm", "LiteLLM"},
	{"mlflow/mlflow", "MLflow"},
	{"wandb/local", "Weights & Biases"},
	// Vector databases
	{"chromadb/chroma", "ChromaDB"},
	{"qdrant/qdrant", "Qdrant"},
	{"semitechnologies/weaviate", "Weaviate"},
	{"weaviate/weaviate", "Weaviate"},
	{"milvusdb/milvus", "Milvus"},
	{"pinecone-io/", "Pinecone"},
	// AI/ML frameworks & notebooks
	{"jupyter/tensorflow-notebook", "Jupyter AI"},
	{"jupyter/pytorch-notebook", "Jupyter AI"},
	{"jupyter/scipy-notebook", "Jupyter AI"},
	{"jupyter/datascience-notebook", "Jupyter AI"},
	{"pytorch/pytorch", "PyTorch"},
	{"tensorflow/tensorflow", "TensorFlow"},
	{"nvcr.io/nvidia/pytorch", "PyTorch"},
	{"nvcr.io/nvidia/tensorflow", "TensorFlow"},
	{"nvidia/tritonserver", "NVIDIA Triton"},
	{"nvcr.io/nvidia/tritonserver", "NVIDIA Triton"},
	// LangChain ecosystem
	{"langchain/", "LangChain"},
	// ClawdBot/OpenClaw/MoltBot
	{"clawdbot/", "ClawdBot"},
	{"openclaw/", "OpenClaw"},
	{"moltbot/", "MoltBot"},
}

// containerInfo holds information about a running container.
type containerInfo struct {
	ID      string
	Image   string
	Name    string
	Ports   string
	Status  string
	EnvVars []string
}

// detectContainerAI enumerates running Docker and Podman containers, looking for
// AI-related images, environment variables, and exposed ports.
func (s *Scanner) detectContainerAI() []DetectionResult {
	var results []DetectionResult

	// Try Docker first, then Podman
	for _, runtime := range []string{"docker", "podman"} {
		containers, err := listContainers(runtime)
		if err != nil {
			if s.Verbose {
				log.Printf("Container runtime %s not available: %v", runtime, err)
			}
			continue
		}

		fmt.Printf("  Found %d %s containers\n", len(containers), runtime)

		for _, c := range containers {
			// Check image name against known AI patterns
			imageLower := strings.ToLower(c.Image)
			for _, ai := range aiContainerImages {
				if strings.Contains(imageLower, strings.ToLower(ai.pattern)) {
					results = append(results, DetectionResult{
						Software:      ai.software,
						DetectionType: "container_image",
						Value:         fmt.Sprintf("Container: %s, Image: %s (%s)", c.Name, c.Image, runtime),
						Path:          fmt.Sprintf("%s://%s", runtime, c.ID),
						Confidence:    "high",
					})
					break
				}
			}

			// Check container environment variables for AI indicators
			envResults := s.checkContainerEnvVars(runtime, c)
			results = append(results, envResults...)

			// Check exposed ports for known AI service ports
			portResults := checkContainerPorts(c, runtime)
			results = append(results, portResults...)
		}
	}

	// Check for Docker Compose files with AI services
	composeResults := s.detectComposeFiles()
	results = append(results, composeResults...)

	return results
}

// listContainers returns info about all running containers for the given runtime.
func listContainers(runtime string) ([]containerInfo, error) {
	// Use JSON format for reliable parsing
	out, err := runCommandTimeout(runtime, "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Ports}}\t{{.Status}}")
	if err != nil {
		return nil, fmt.Errorf("%s not available: %w", runtime, err)
	}

	var containers []containerInfo
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) < 2 {
			continue
		}
		c := containerInfo{
			ID:    parts[0],
			Image: parts[1],
		}
		if len(parts) > 2 {
			c.Name = parts[2]
		}
		if len(parts) > 3 {
			c.Ports = parts[3]
		}
		if len(parts) > 4 {
			c.Status = parts[4]
		}
		containers = append(containers, c)
	}
	return containers, nil
}

// checkContainerEnvVars inspects a container's environment variables for AI-related keys.
func (s *Scanner) checkContainerEnvVars(runtime string, c containerInfo) []DetectionResult {
	var results []DetectionResult

	// Use docker/podman inspect to get environment variables
	out, err := runCommandTimeout(runtime, "inspect", "--format", "{{json .Config.Env}}", c.ID)
	if err != nil {
		return results
	}

	var envVars []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &envVars); err != nil {
		return results
	}

	aiEnvPatterns := []struct {
		pattern  string
		software string
	}{
		{"OPENAI_API_KEY", "AI API Provider"},
		{"ANTHROPIC_API_KEY", "AI API Provider"},
		{"OLLAMA_", "Ollama"},
		{"VLLM_", "vLLM"},
		{"LITELLM_", "LiteLLM"},
		{"N8N_", "n8n"},
		{"FLOWISE_", "FlowiseAI"},
		{"DIFY_", "Dify"},
		{"LANGCHAIN_", "LangChain"},
		{"OPENROUTER_", "OpenRouter"},
		{"HUGGINGFACE_", "HuggingFace"},
		{"HF_TOKEN", "HuggingFace"},
		{"GROQ_API_KEY", "AI API Provider"},
		{"MISTRAL_API_KEY", "AI API Provider"},
		{"COHERE_API_KEY", "AI API Provider"},
		{"TOGETHER_API_KEY", "AI API Provider"},
		{"REPLICATE_API_TOKEN", "AI API Provider"},
		{"DEEPSEEK_API_KEY", "AI API Provider"},
		{"CHROMA_", "ChromaDB"},
		{"QDRANT_", "Qdrant"},
		{"WEAVIATE_", "Weaviate"},
		{"MILVUS_", "Milvus"},
		{"PINECONE_", "Pinecone"},
		{"WANDB_", "Weights & Biases"},
		{"MLFLOW_", "MLflow"},
		{"CLAWDBOT_", "ClawdBot"},
		{"OPENCLAW_", "OpenClaw"},
		{"MOLTBOT_", "MoltBot"},
	}

	for _, env := range envVars {
		envUpper := strings.ToUpper(env)
		for _, pat := range aiEnvPatterns {
			if strings.Contains(envUpper, pat.pattern) {
				results = append(results, DetectionResult{
					Software:      pat.software,
					DetectionType: "container_env_var",
					Value:         fmt.Sprintf("Container %s (%s): %s", c.Name, runtime, maskEnvValue(env)),
					Path:          fmt.Sprintf("%s://%s", runtime, c.ID),
					Confidence:    "high",
				})
				break
			}
		}
	}
	return results
}

// checkContainerPorts checks if a container exposes known AI service ports.
func checkContainerPorts(c containerInfo, runtime string) []DetectionResult {
	var results []DetectionResult

	aiPorts := map[string]string{
		"11434": "Ollama",
		"8000":  "vLLM",
		"1234":  "LM Studio",
		"3000":  "Open WebUI",
		"5678":  "n8n",
		"3001":  "FlowiseAI",
		"5001":  "Dify",
		"8080":  "LocalAI",
		"4891":  "GPT4All",
		"8265":  "LiteLLM",
		"8501":  "Streamlit",
		"7860":  "Gradio",
		"8888":  "Jupyter",
		"5000":  "MLflow",
		"6333":  "Qdrant",
		"8529":  "Weaviate",
		"19530": "Milvus",
		"8002":  "NVIDIA Triton",
	}

	portsLower := strings.ToLower(c.Ports)
	for port, software := range aiPorts {
		if strings.Contains(portsLower, ":"+port+"->") || strings.Contains(portsLower, ":"+port+"/") {
			results = append(results, DetectionResult{
				Software:      software,
				DetectionType: "container_port",
				Value:         fmt.Sprintf("Container %s (%s) exposes port %s (%s)", c.Name, runtime, port, software),
				Path:          fmt.Sprintf("%s://%s", runtime, c.ID),
				Confidence:    "medium",
			})
		}
	}
	return results
}

// detectComposeFiles searches for Docker Compose files containing AI services.
func (s *Scanner) detectComposeFiles() []DetectionResult {
	var results []DetectionResult
	home := userHomeDir()

	// Common locations for Docker Compose files
	searchDirs := []string{
		home,
		home + "/docker",
		home + "/containers",
		home + "/projects",
		home + "/workspace",
		home + "/dev",
		"/opt",
		"/srv",
		"/etc/docker",
	}

	composeNames := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
		"compose.yaml",
	}

	for _, dir := range searchDirs {
		for _, name := range composeNames {
			path := dir + "/" + name
			if !pathExists(path) {
				continue
			}
			// Read the compose file and look for AI image references
			results = append(results, s.scanComposeFile(path)...)
		}
	}
	return results
}

// scanComposeFile reads a Docker Compose file and checks for AI-related images.
func (s *Scanner) scanComposeFile(path string) []DetectionResult {
	var results []DetectionResult

	data, err := readFileSafe(path, 1024*1024) // 1MB max
	if err != nil {
		return results
	}

	contentLower := strings.ToLower(string(data))

	for _, ai := range aiContainerImages {
		if strings.Contains(contentLower, strings.ToLower(ai.pattern)) {
			results = append(results, DetectionResult{
				Software:      ai.software,
				DetectionType: "container_compose",
				Value:         fmt.Sprintf("Docker Compose references %s image: %s", ai.software, path),
				Path:          path,
				Confidence:    "high",
			})
		}
	}
	return results
}

// maskEnvValue masks the value portion of an environment variable for security.
func maskEnvValue(env string) string {
	parts := strings.SplitN(env, "=", 2)
	if len(parts) != 2 {
		return env
	}
	key := parts[0]
	val := parts[1]

	// Mask sensitive values (API keys, passwords, tokens)
	sensitive := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"}
	keyUpper := strings.ToUpper(key)
	for _, s := range sensitive {
		if strings.Contains(keyUpper, s) {
			if len(val) > 8 {
				return key + "=" + val[:4] + "****" + val[len(val)-4:]
			}
			return key + "=****"
		}
	}
	return env
}

// readFileSafe reads a file up to maxBytes, returning the content or an error.
func readFileSafe(path string, maxBytes int64) ([]byte, error) {
	f, err := openFileSafe(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file too large: %d bytes", info.Size())
	}

	buf := make([]byte, info.Size())
	n, err := f.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// openFileSafe opens a file with basic path validation.
func openFileSafe(path string) (*os.File, error) {
	clean, err := sanitizePath(path)
	if err != nil || clean == "" {
		return nil, fmt.Errorf("invalid path: %s", path)
	}
	return os.Open(clean)
}
