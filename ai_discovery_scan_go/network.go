package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Known AI domains → software name
// ---------------------------------------------------------------------------

var aiDomainMap = map[string]string{
	// OpenAI
	"api.openai.com":      "OpenAI",
	"platform.openai.com": "OpenAI",
	"chat.openai.com":     "OpenAI",
	"cdn.openai.com":      "OpenAI",
	"auth0.openai.com":    "OpenAI",
	// Anthropic
	"api.anthropic.com":     "Anthropic",
	"console.anthropic.com": "Anthropic",
	"docs.anthropic.com":    "Anthropic",
	// Google AI
	"generativelanguage.googleapis.com": "Google AI",
	"aiplatform.googleapis.com":         "Google AI",
	"aistudio.google.com":               "Google AI",
	"gemini.google.com":                 "Google AI",
	// Mistral
	"api.mistral.ai":     "Mistral",
	"console.mistral.ai": "Mistral",
	"chat.mistral.ai":    "Mistral",
	// Cohere
	"api.cohere.ai":  "Cohere",
	"api.cohere.com": "Cohere",
	// Groq
	"api.groq.com":     "Groq",
	"console.groq.com": "Groq",
	// Together AI
	"api.together.xyz": "Together AI",
	"api.together.ai":  "Together AI",
	// Replicate
	"api.replicate.com": "Replicate",
	// Fireworks AI
	"api.fireworks.ai": "Fireworks AI",
	// DeepSeek
	"api.deepseek.com":  "DeepSeek",
	"chat.deepseek.com": "DeepSeek",
	// xAI / Grok
	"api.x.ai":     "xAI",
	"console.x.ai": "xAI",
	"grok.x.ai":    "xAI",
	// Stability AI
	"api.stability.ai": "Stability AI",
	// Perplexity
	"api.perplexity.ai": "Perplexity",
	// HuggingFace
	"api-inference.huggingface.co": "HuggingFace",
	"huggingface.co":               "HuggingFace",
	// AI21
	"api.ai21.com":    "AI21 Labs",
	"studio.ai21.com": "AI21 Labs",
	// SambaNova
	"api.sambanova.ai": "SambaNova",
	// Cerebras
	"api.cerebras.ai": "Cerebras",
	// Reka
	"api.reka.ai": "Reka",
	// Writer
	"api.writer.com":            "Writer",
	"enterprise-api.writer.com": "Writer",
	// Voyage AI
	"api.voyageai.com": "Voyage AI",
	// AI Proxy / Gateways
	"openrouter.ai":      "OpenRouter",
	"api.helicone.ai":    "Helicone",
	"api.portkey.ai":     "Portkey",
	"smith.langchain.com": "LangSmith",
	"api.wandb.ai":       "Weights & Biases",
	// ClawdBot
	"clawdbot.ai":     "ClawdBot",
	"clawdbot.com":    "ClawdBot",
	"api.clawdbot.ai": "ClawdBot",
	"api.clawdbot.com": "ClawdBot",
	// OpenClaw
	"openclaw.ai":     "OpenClaw",
	"api.openclaw.ai": "OpenClaw",
	// MoltBot
	"moltbot.ai":     "MoltBot",
	"api.moltbot.ai": "MoltBot",
}

var aiDomainSuffixes = []struct {
	suffix   string
	software string
}{
	{".openai.com", "OpenAI"},
	{".anthropic.com", "Anthropic"},
	{".mistral.ai", "Mistral"},
	{".cohere.ai", "Cohere"},
	{".cohere.com", "Cohere"},
	{".groq.com", "Groq"},
	{".together.xyz", "Together AI"},
	{".together.ai", "Together AI"},
	{".replicate.com", "Replicate"},
	{".fireworks.ai", "Fireworks AI"},
	{".deepseek.com", "DeepSeek"},
	{".x.ai", "xAI"},
	{".stability.ai", "Stability AI"},
	{".perplexity.ai", "Perplexity"},
	{".huggingface.co", "HuggingFace"},
	{".ai21.com", "AI21 Labs"},
	{".sambanova.ai", "SambaNova"},
	{".cerebras.ai", "Cerebras"},
	{".reka.ai", "Reka"},
	{".writer.com", "Writer"},
	{".voyageai.com", "Voyage AI"},
	{".clawdbot.ai", "ClawdBot"},
	{".clawdbot.com", "ClawdBot"},
	{".openclaw.ai", "OpenClaw"},
	{".moltbot.ai", "MoltBot"},
}

// Known AI service ports for local listening detection.
var aiLocalServicePorts = map[int]string{
	11434: "Ollama",
	1234:  "LM Studio",
	4891:  "GPT4All",
	8000:  "vLLM",
	3000:  "Open WebUI",
	5678:  "n8n",
	3001:  "FlowiseAI",
	5001:  "Dify",
	8080:  "LocalAI",
	8265:  "LiteLLM",
	8501:  "Streamlit",
	7860:  "Gradio",
	8888:  "Jupyter",
	5000:  "MLflow",
	6333:  "Qdrant",
	8529:  "Weaviate",
	19530: "Milvus",
	8002:  "NVIDIA Triton",
}

// ---------------------------------------------------------------------------
// detectNetworkAI runs all network-based detection methods.
// ---------------------------------------------------------------------------

func (s *Scanner) detectNetworkAI() []DetectionResult {
	var results []DetectionResult

	results = append(results, s.detectActiveAIConnections()...)
	results = append(results, s.detectListeningAIPorts()...)
	results = append(results, s.detectDNSCacheAIDomains()...)

	return results
}

// ---------------------------------------------------------------------------
// 1. Active TCP connection analysis
// ---------------------------------------------------------------------------

func (s *Scanner) detectActiveAIConnections() []DetectionResult {
	var results []DetectionResult

	conns := listEstablishedTCP()
	seen := make(map[string]bool)

	for _, c := range conns {
		if isLoopback(c.remoteIP) {
			continue
		}

		hostname := reverseLookup(c.remoteIP)
		software := matchDomain(hostname)

		if software != "" {
			key := fmt.Sprintf("%s:%s", software, c.remoteIP)
			if !seen[key] {
				seen[key] = true
				results = append(results, DetectionResult{
					Software:      software,
					DetectionType: "network_connection",
					Value: fmt.Sprintf("Active connection to %s: %s:%d (%s)",
						software, c.remoteIP, c.remotePort, hostname),
					Confidence: "high",
				})
			}
		}

		// Check known AI port on remote host
		if software == "" {
			if portSw, ok := aiLocalServicePorts[c.remotePort]; ok {
				key := fmt.Sprintf("port:%s:%s", portSw, c.remoteIP)
				if !seen[key] {
					seen[key] = true
					results = append(results, DetectionResult{
						Software:      portSw,
						DetectionType: "network_connection",
						Value: fmt.Sprintf("Connection to remote %s port: %s:%d",
							portSw, c.remoteIP, c.remotePort),
						Confidence: "low",
					})
				}
			}
		}
	}

	return results
}

// ---------------------------------------------------------------------------
// 2. Listening port detection
// ---------------------------------------------------------------------------

func (s *Scanner) detectListeningAIPorts() []DetectionResult {
	var results []DetectionResult

	listeners := listListeningTCP()
	seen := make(map[int]bool)

	for _, l := range listeners {
		if sw, ok := aiLocalServicePorts[l.localPort]; ok && !seen[l.localPort] {
			seen[l.localPort] = true
			results = append(results, DetectionResult{
				Software:      sw,
				DetectionType: "network_listen",
				Value:         fmt.Sprintf("Listening on port %d (%s)", l.localPort, sw),
				Confidence:    "medium",
			})
		}
	}

	return results
}

// ---------------------------------------------------------------------------
// 3. DNS cache inspection
// ---------------------------------------------------------------------------

func (s *Scanner) detectDNSCacheAIDomains() []DetectionResult {
	var results []DetectionResult

	var entries []string
	switch runtime.GOOS {
	case "windows":
		entries = getDNSCacheWindows()
	case "linux":
		entries = getDNSCacheLinux()
	case "darwin":
		entries = getDNSCacheMacOS()
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		lower := strings.ToLower(strings.TrimSpace(entry))

		for domain, software := range aiDomainMap {
			if strings.Contains(lower, domain) {
				key := fmt.Sprintf("dns:%s:%s", software, domain)
				if !seen[key] {
					seen[key] = true
					results = append(results, DetectionResult{
						Software:      software,
						DetectionType: "dns_cache",
						Value:         fmt.Sprintf("DNS cache contains %s domain: %s", software, domain),
						Confidence:    "medium",
					})
				}
			}
		}

		for _, s := range aiDomainSuffixes {
			if strings.Contains(lower, s.suffix) {
				key := fmt.Sprintf("dns_suffix:%s", s.software)
				if !seen[key] {
					seen[key] = true
					results = append(results, DetectionResult{
						Software:      s.software,
						DetectionType: "dns_cache",
						Value:         fmt.Sprintf("DNS cache contains %s domain (suffix match: *%s)", s.software, s.suffix),
						Confidence:    "medium",
					})
				}
			}
		}
	}

	return results
}

// ---------------------------------------------------------------------------
// TCP connection helpers (cross-platform via /proc, netstat, ss)
// ---------------------------------------------------------------------------

type tcpConn struct {
	localIP    string
	localPort  int
	remoteIP   string
	remotePort int
}

func listEstablishedTCP() []tcpConn {
	switch runtime.GOOS {
	case "linux":
		return parseProcNet("/proc/net/tcp", "01") // 01 = ESTABLISHED
	default:
		return parseNetstat("ESTABLISHED")
	}
}

func listListeningTCP() []tcpConn {
	switch runtime.GOOS {
	case "linux":
		return parseProcNet("/proc/net/tcp", "0A") // 0A = LISTEN
	default:
		return parseNetstat("LISTEN")
	}
}

// parseProcNet reads /proc/net/tcp on Linux and returns connections matching
// the given hex state code.
func parseProcNet(path, stateHex string) []tcpConn {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []tcpConn
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false // skip header
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] != stateHex {
			continue
		}
		localIP, localPort := parseHexAddr(fields[1])
		remoteIP, remotePort := parseHexAddr(fields[2])
		out = append(out, tcpConn{localIP, localPort, remoteIP, remotePort})
	}
	return out
}

// parseHexAddr converts "0100007F:1F90" → ("127.0.0.1", 8080).
func parseHexAddr(s string) (string, int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	ipHex := parts[0]
	portHex := parts[1]

	port64, _ := strconv.ParseInt(portHex, 16, 32)
	port := int(port64)

	// Linux stores IPv4 in little-endian hex
	if len(ipHex) == 8 {
		v, _ := strconv.ParseUint(ipHex, 16, 32)
		b0 := byte(v & 0xFF)
		b1 := byte((v >> 8) & 0xFF)
		b2 := byte((v >> 16) & 0xFF)
		b3 := byte((v >> 24) & 0xFF)
		return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3), port
	}
	return ipHex, port
}

// parseNetstat uses netstat output on macOS/Windows for connections in the
// given state.
func parseNetstat(state string) []tcpConn {
	out, err := runCommandTimeout("netstat", "-an")
	if err != nil {
		return nil
	}

	var conns []tcpConn
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, state) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Typical: proto local_addr remote_addr state
		if !strings.HasPrefix(strings.ToLower(fields[0]), "tcp") {
			continue
		}
		localIP, localPort := splitHostPort(fields[3])
		remoteIP, remotePort := splitHostPort(fields[4])
		if remoteIP != "" {
			conns = append(conns, tcpConn{localIP, localPort, remoteIP, remotePort})
		}
	}
	return conns
}

// splitHostPort splits "192.168.1.1:443" or "192.168.1.1.443" (macOS).
func splitHostPort(s string) (string, int) {
	// Try standard host:port first
	host, portStr, err := net.SplitHostPort(s)
	if err == nil {
		p, _ := strconv.Atoi(portStr)
		return host, p
	}
	// macOS uses "192.168.1.1.443" format – last dot-separated segment is the port
	idx := strings.LastIndex(s, ".")
	if idx > 0 {
		p, err := strconv.Atoi(s[idx+1:])
		if err == nil {
			return s[:idx], p
		}
	}
	return s, 0
}

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1" || ip == "0.0.0.0"
}

// reverseLookup performs a reverse DNS lookup with a short timeout.
func reverseLookup(ip string) string {
	done := make(chan string, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			done <- ""
			return
		}
		done <- strings.TrimSuffix(names[0], ".")
	}()

	select {
	case name := <-done:
		return name
	case <-time.After(2 * time.Second):
		return ""
	}
}

// matchDomain checks if a hostname matches any known AI domain.
func matchDomain(hostname string) string {
	if hostname == "" {
		return ""
	}
	lower := strings.ToLower(hostname)

	if sw, ok := aiDomainMap[lower]; ok {
		return sw
	}
	for _, s := range aiDomainSuffixes {
		if strings.HasSuffix(lower, s.suffix) {
			return s.software
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// DNS cache retrieval per platform
// ---------------------------------------------------------------------------

func getDNSCacheWindows() []string {
	out, err := runCommandTimeout("ipconfig", "/displaydns")
	if err != nil {
		return nil
	}
	return strings.Split(out, "\n")
}

func getDNSCacheLinux() []string {
	// Try systemd-resolved cache
	for _, cmd := range [][]string{
		{"resolvectl", "query", "--cache"},
		{"systemd-resolve", "--statistics"},
	} {
		out, err := runCommandTimeout(cmd[0], cmd[1:]...)
		if err == nil {
			return strings.Split(out, "\n")
		}
	}

	// Fallback: check /etc/hosts
	f, err := os.Open("/etc/hosts")
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func getDNSCacheMacOS() []string {
	var lines []string

	// Check /etc/hosts
	f, err := os.Open("/etc/hosts")
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		f.Close()
	}

	// Try mDNSResponder log
	out, err := runCommandTimeout("log", "show",
		"--predicate", "process == 'mDNSResponder'",
		"--last", "5m", "--style", "compact")
	if err == nil {
		lines = append(lines, strings.Split(out, "\n")...)
	}

	return lines
}

func init() {
	// Ensure the logger is available
	_ = log.Prefix()
}
