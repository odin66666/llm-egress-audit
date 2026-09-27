"""Paths, environment overrides and the list of known LLM API hosts."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP = "llm-egress-audit"

# Hosts that receive prompts. Everything that crosses the proxy is recorded anyway;
# this list only decides which destinations are classified as "llm" in reports.
LLM_HOST_SUFFIXES = (
    "api.anthropic.com",
    "claude.ai",
    "api.openai.com",
    "chatgpt.com",
    "openai.azure.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "api.mistral.ai",
    "api.cohere.com",
    "api.cohere.ai",
    "api.groq.com",
    "api.deepseek.com",
    "openrouter.ai",
    "api.x.ai",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.perplexity.ai",
    "githubcopilot.com",
    "cursor.sh",
    "cursor.com",
    "api.moonshot.ai",
    "dashscope.aliyuncs.com",
    "open.bigmodel.cn",
    "api.z.ai",
)
LLM_HOST_FRAGMENTS = ("bedrock-runtime.",)


def home() -> Path:
    env = os.environ.get("LLM_EGRESS_AUDIT_HOME")
    if env:
        return Path(env).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP


def key_path() -> Path:
    env = os.environ.get("LLM_EGRESS_AUDIT_KEYFILE")
    return Path(env).expanduser() if env else home() / "key"


def db_path() -> Path:
    return home() / "egress.sqlite3"


def mitm_ca_cert() -> Path:
    confdir = os.environ.get("MITMPROXY_CONFDIR")
    base = Path(confdir).expanduser() if confdir else Path.home() / ".mitmproxy"
    return base / "mitmproxy-ca-cert.pem"


def extra_llm_hosts() -> tuple:
    raw = os.environ.get("LLM_EGRESS_AUDIT_LLM_HOSTS", "")
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


def is_llm_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    for suffix in LLM_HOST_SUFFIXES + extra_llm_hosts():
        if host == suffix or host.endswith("." + suffix):
            return True
    return any(fragment in host for fragment in LLM_HOST_FRAGMENTS)
