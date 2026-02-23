#!/usr/bin/env python3
"""
Network Detection Module for AI Discovery Scanner
===================================================

Provides active network connection analysis to detect AI/LLM service
communication. Inspects live TCP connections, resolves remote endpoints,
and correlates them against known AI API provider domains and ports.

Detection Methods:
- Active TCP connection monitoring via psutil
- DNS resolution of remote endpoints to identify AI domains
- Known AI service port correlation on remote hosts
- Local listening port detection for AI services
- DNS cache inspection (platform-dependent)

Author: Security Team
Version: 1.0.0
License: MIT
"""

import logging
import os
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)

# Timeout for DNS reverse lookups (seconds)
DNS_LOOKUP_TIMEOUT = 2

# Subprocess timeout for system commands
SUBPROCESS_TIMEOUT = 15

# -----------------------------------------------------------------------
# Known AI domains mapped to software names
# -----------------------------------------------------------------------
AI_DOMAIN_MAP: Dict[str, str] = {
    # OpenAI
    "api.openai.com": "OpenAI",
    "platform.openai.com": "OpenAI",
    "chat.openai.com": "OpenAI",
    "cdn.openai.com": "OpenAI",
    "auth0.openai.com": "OpenAI",
    # Anthropic
    "api.anthropic.com": "Anthropic",
    "console.anthropic.com": "Anthropic",
    "docs.anthropic.com": "Anthropic",
    # Google AI
    "generativelanguage.googleapis.com": "Google AI",
    "aiplatform.googleapis.com": "Google AI",
    "aistudio.google.com": "Google AI",
    "gemini.google.com": "Google AI",
    # Mistral
    "api.mistral.ai": "Mistral",
    "console.mistral.ai": "Mistral",
    "chat.mistral.ai": "Mistral",
    # Cohere
    "api.cohere.ai": "Cohere",
    "api.cohere.com": "Cohere",
    # Groq
    "api.groq.com": "Groq",
    "console.groq.com": "Groq",
    # Together AI
    "api.together.xyz": "Together AI",
    "api.together.ai": "Together AI",
    # Replicate
    "api.replicate.com": "Replicate",
    # Fireworks AI
    "api.fireworks.ai": "Fireworks AI",
    # DeepSeek
    "api.deepseek.com": "DeepSeek",
    "chat.deepseek.com": "DeepSeek",
    # xAI / Grok
    "api.x.ai": "xAI",
    "console.x.ai": "xAI",
    "grok.x.ai": "xAI",
    # Stability AI
    "api.stability.ai": "Stability AI",
    # Perplexity
    "api.perplexity.ai": "Perplexity",
    # HuggingFace
    "api-inference.huggingface.co": "HuggingFace",
    "huggingface.co": "HuggingFace",
    # AI21
    "api.ai21.com": "AI21 Labs",
    "studio.ai21.com": "AI21 Labs",
    # SambaNova
    "api.sambanova.ai": "SambaNova",
    # Cerebras
    "api.cerebras.ai": "Cerebras",
    # Reka
    "api.reka.ai": "Reka",
    # Writer
    "api.writer.com": "Writer",
    "enterprise-api.writer.com": "Writer",
    # Voyage AI
    "api.voyageai.com": "Voyage AI",
    # AI Proxy / Gateways
    "openrouter.ai": "OpenRouter",
    "api.helicone.ai": "Helicone",
    "api.portkey.ai": "Portkey",
    "smith.langchain.com": "LangSmith",
    "api.wandb.ai": "Weights & Biases",
    # ClawdBot
    "clawdbot.ai": "ClawdBot",
    "clawdbot.com": "ClawdBot",
    "api.clawdbot.ai": "ClawdBot",
    "api.clawdbot.com": "ClawdBot",
    # OpenClaw
    "openclaw.ai": "OpenClaw",
    "api.openclaw.ai": "OpenClaw",
    # MoltBot
    "moltbot.ai": "MoltBot",
    "api.moltbot.ai": "MoltBot",
}

# Partial domain suffixes to match (for wildcard-style detection)
AI_DOMAIN_SUFFIXES: List[Tuple[str, str]] = [
    (".openai.com", "OpenAI"),
    (".anthropic.com", "Anthropic"),
    (".mistral.ai", "Mistral"),
    (".cohere.ai", "Cohere"),
    (".cohere.com", "Cohere"),
    (".groq.com", "Groq"),
    (".together.xyz", "Together AI"),
    (".together.ai", "Together AI"),
    (".replicate.com", "Replicate"),
    (".fireworks.ai", "Fireworks AI"),
    (".deepseek.com", "DeepSeek"),
    (".x.ai", "xAI"),
    (".stability.ai", "Stability AI"),
    (".perplexity.ai", "Perplexity"),
    (".huggingface.co", "HuggingFace"),
    (".ai21.com", "AI21 Labs"),
    (".sambanova.ai", "SambaNova"),
    (".cerebras.ai", "Cerebras"),
    (".reka.ai", "Reka"),
    (".writer.com", "Writer"),
    (".voyageai.com", "Voyage AI"),
    (".clawdbot.ai", "ClawdBot"),
    (".clawdbot.com", "ClawdBot"),
    (".openclaw.ai", "OpenClaw"),
    (".moltbot.ai", "MoltBot"),
]

# Known AI service ports on localhost
AI_LOCAL_SERVICE_PORTS: Dict[int, str] = {
    11434: "Ollama",
    1234: "LM Studio",
    4891: "GPT4All",
    8000: "vLLM",
    3000: "Open WebUI",
    5678: "n8n",
    3001: "FlowiseAI",
    5001: "Dify",
    8080: "LocalAI",
    8265: "LiteLLM",
    8501: "Streamlit",
    7860: "Gradio",
    8888: "Jupyter",
    5000: "MLflow",
    6333: "Qdrant",
    8529: "Weaviate",
    19530: "Milvus",
    8002: "NVIDIA Triton",
}

# Common HTTPS/HTTP ports used by AI APIs (remote connections)
AI_REMOTE_PORTS = {443, 80, 8443}


@dataclass
class NetworkDetectionResult:
    """A single network-based detection finding."""
    software: str
    detection_type: str
    value: str
    path: Optional[str] = None
    confidence: str = "medium"


class NetworkDetector:
    """Detects AI service usage via active network connection analysis."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._reverse_dns_cache: Dict[str, Optional[str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect_all(self) -> List[NetworkDetectionResult]:
        """Run all network-based detection methods and return results."""
        results: List[NetworkDetectionResult] = []

        results.extend(self.detect_active_ai_connections())
        results.extend(self.detect_listening_ai_ports())
        results.extend(self.detect_dns_cache_ai_domains())

        return results

    # ------------------------------------------------------------------
    # 1. Active TCP connection analysis
    # ------------------------------------------------------------------

    def detect_active_ai_connections(self) -> List[NetworkDetectionResult]:
        """Inspect active TCP connections for traffic to known AI endpoints."""
        results: List[NetworkDetectionResult] = []

        if psutil is None:
            logger.warning("psutil not available; skipping active connection detection")
            return results

        seen: Set[str] = set()

        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError) as exc:
            logger.debug(f"Cannot enumerate connections: {exc}")
            return results

        for conn in connections:
            if conn.status != "ESTABLISHED":
                continue

            raddr = conn.raddr
            if not raddr:
                continue

            remote_ip = raddr.ip
            remote_port = raddr.port

            # Skip loopback – handled separately in listening-port detection
            if remote_ip.startswith("127.") or remote_ip == "::1":
                continue

            # Attempt reverse DNS to identify the remote host
            hostname = self._reverse_lookup(remote_ip)

            software = self._match_domain(hostname) if hostname else None

            if software and f"{software}:{remote_ip}" not in seen:
                seen.add(f"{software}:{remote_ip}")

                pid_info = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        pid_info = f", Process: {proc.name()} (PID {conn.pid})"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pid_info = f", PID: {conn.pid}"

                results.append(NetworkDetectionResult(
                    software=software,
                    detection_type="network_connection",
                    value=(
                        f"Active connection to {software}: "
                        f"{remote_ip}:{remote_port} ({hostname}){pid_info}"
                    ),
                    confidence="high",
                ))

            # Also check if the remote port matches a known AI service
            # (for non-standard hosting / self-hosted endpoints)
            if remote_port in AI_LOCAL_SERVICE_PORTS and not software:
                port_software = AI_LOCAL_SERVICE_PORTS[remote_port]
                key = f"port:{port_software}:{remote_ip}"
                if key not in seen:
                    seen.add(key)
                    results.append(NetworkDetectionResult(
                        software=port_software,
                        detection_type="network_connection",
                        value=(
                            f"Connection to remote {port_software} port: "
                            f"{remote_ip}:{remote_port}"
                        ),
                        confidence="low",
                    ))

        return results

    # ------------------------------------------------------------------
    # 2. Local listening port detection
    # ------------------------------------------------------------------

    def detect_listening_ai_ports(self) -> List[NetworkDetectionResult]:
        """Detect local services listening on known AI ports."""
        results: List[NetworkDetectionResult] = []

        if psutil is None:
            logger.warning("psutil not available; skipping listening port detection")
            return results

        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError) as exc:
            logger.debug(f"Cannot enumerate connections: {exc}")
            return results

        seen: Set[int] = set()

        for conn in connections:
            if conn.status != "LISTEN":
                continue

            laddr = conn.laddr
            if not laddr:
                continue

            port = laddr.port
            if port in AI_LOCAL_SERVICE_PORTS and port not in seen:
                seen.add(port)
                software = AI_LOCAL_SERVICE_PORTS[port]

                pid_info = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        pid_info = f", Process: {proc.name()} (PID {conn.pid})"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pid_info = f", PID: {conn.pid}"

                results.append(NetworkDetectionResult(
                    software=software,
                    detection_type="network_listen",
                    value=f"Listening on port {port} ({software}){pid_info}",
                    confidence="medium",
                ))

        return results

    # ------------------------------------------------------------------
    # 3. DNS cache inspection
    # ------------------------------------------------------------------

    def detect_dns_cache_ai_domains(self) -> List[NetworkDetectionResult]:
        """Inspect the system DNS cache for AI-related domain resolutions."""
        results: List[NetworkDetectionResult] = []

        system = platform.system()
        cache_entries: List[str] = []

        if system == "Windows":
            cache_entries = self._get_dns_cache_windows()
        elif system == "Linux":
            cache_entries = self._get_dns_cache_linux()
        elif system == "Darwin":
            cache_entries = self._get_dns_cache_macos()

        seen: Set[str] = set()
        for entry in cache_entries:
            entry_lower = entry.lower().strip()

            # Check exact domain map
            for domain, software in AI_DOMAIN_MAP.items():
                if domain in entry_lower:
                    key = f"dns:{software}:{domain}"
                    if key not in seen:
                        seen.add(key)
                        results.append(NetworkDetectionResult(
                            software=software,
                            detection_type="dns_cache",
                            value=f"DNS cache contains {software} domain: {domain}",
                            confidence="medium",
                        ))

            # Check suffix patterns
            for suffix, software in AI_DOMAIN_SUFFIXES:
                if suffix in entry_lower:
                    key = f"dns_suffix:{software}"
                    if key not in seen:
                        seen.add(key)
                        results.append(NetworkDetectionResult(
                            software=software,
                            detection_type="dns_cache",
                            value=f"DNS cache contains {software} domain (suffix match: *{suffix})",
                            confidence="medium",
                        ))

        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform a cached reverse DNS lookup with timeout."""
        if ip in self._reverse_dns_cache:
            return self._reverse_dns_cache[ip]

        hostname = None
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(DNS_LOOKUP_TIMEOUT)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.herror, socket.gaierror, OSError):
            pass

        self._reverse_dns_cache[ip] = hostname
        return hostname

    def _match_domain(self, hostname: str) -> Optional[str]:
        """Check if *hostname* matches any known AI domain."""
        if not hostname:
            return None

        hostname_lower = hostname.lower()

        # Exact match
        if hostname_lower in AI_DOMAIN_MAP:
            return AI_DOMAIN_MAP[hostname_lower]

        # Suffix match
        for suffix, software in AI_DOMAIN_SUFFIXES:
            if hostname_lower.endswith(suffix):
                return software

        return None

    # -- DNS cache retrieval per platform --

    @staticmethod
    def _get_dns_cache_windows() -> List[str]:
        """Read DNS cache on Windows via ipconfig /displaydns."""
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode == 0:
                return result.stdout.splitlines()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return []

    @staticmethod
    def _get_dns_cache_linux() -> List[str]:
        """Read DNS cache on Linux via systemd-resolve --statistics or journalctl."""
        lines: List[str] = []

        # Try systemd-resolved cache dump (available on Ubuntu, Fedora, etc.)
        for cmd in [
            ["resolvectl", "query", "--cache"],
            ["systemd-resolve", "--statistics"],
        ]:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
                )
                if result.returncode == 0:
                    lines.extend(result.stdout.splitlines())
                    return lines
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue

        # Fallback: check /etc/hosts for hardcoded AI domains
        try:
            with open("/etc/hosts", "r") as fh:
                lines.extend(fh.read().splitlines())
        except OSError:
            pass

        return lines

    @staticmethod
    def _get_dns_cache_macos() -> List[str]:
        """Read DNS cache on macOS (limited — macOS has no user-accessible cache dump)."""
        lines: List[str] = []

        # macOS: check /etc/hosts
        try:
            with open("/etc/hosts", "r") as fh:
                lines.extend(fh.read().splitlines())
        except OSError:
            pass

        # Optionally check mDNSResponder log snippets
        try:
            result = subprocess.run(
                ["log", "show", "--predicate", "process == 'mDNSResponder'",
                 "--last", "5m", "--style", "compact"],
                capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode == 0:
                lines.extend(result.stdout.splitlines())
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return lines
