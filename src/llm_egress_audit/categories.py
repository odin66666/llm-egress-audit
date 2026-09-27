"""What kind of destination a request went to.

A category comes from the host *and* the path: the same host often serves several
purposes (api.anthropic.com answers prompts on /v1/messages and collects telemetry on
/api/event_logging). Rules are checked in order; the first match wins.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

from .config import is_llm_host

LLM = "llm"
TELEMETRY = "telemetry"
ERRORS = "error-reporting"
AUTH = "auth"
TOOLS = "tools/mcp"
SEARCH = "web/search"
STORAGE = "cloud-storage"
DEV = "dev-services"
OTHER = "other"

# Order used in reports: where content ends up matters most first.
ORDER = (LLM, TELEMETRY, ERRORS, STORAGE, SEARCH, TOOLS, DEV, AUTH, OTHER)

DESCRIPTIONS = {
    LLM: "prompt sent to a model",
    TELEMETRY: "usage analytics, metrics, logs",
    ERRORS: "crash and error reports",
    STORAGE: "file storage and uploads",
    SEARCH: "web search and page fetches",
    TOOLS: "tool integrations, MCP servers and registries",
    DEV: "code hosting and package registries",
    AUTH: "login, tokens, account data",
    OTHER: "not classified",
}

_HOSTS = (
    (TELEMETRY, ("datadoghq.com", "datadoghq.eu", "statsig.com", "statsigapi.net", "featuregates.org",
                 "segment.io", "segment.com", "mixpanel.com", "amplitude.com", "posthog.com",
                 "google-analytics.com", "analytics.google.com", "honeycomb.io", "launchdarkly.com",
                 "growthbook.io", "newrelic.com", "nr-data.net", "clarity.ms", "doubleclick.net",
                 "play.googleapis.com", "firebaselogging-pa.googleapis.com", "app-measurement.com",
                 "ab.chatgpt.com")),
    (ERRORS, ("sentry.io", "ingest.sentry.io", "bugsnag.com", "rollbar.com", "crashlytics.com",
              "raygun.io", "honeybadger.io")),
    (AUTH, ("accounts.google.com", "oauth2.googleapis.com", "auth.openai.com", "auth0.openai.com",
            "login.microsoftonline.com", "console.anthropic.com", "securetoken.googleapis.com")),
    (TOOLS, ("mcp-proxy.anthropic.com",)),
    (SEARCH, ("bing.com", "duckduckgo.com", "search.brave.com", "api.search.brave.com",
              "serpapi.com", "api.tavily.com", "api.exa.ai", "customsearch.googleapis.com",
              "r.jina.ai", "s.jina.ai")),
    (STORAGE, ("drive.google.com", "docs.google.com", "storage.googleapis.com", "dropbox.com",
               "dropboxapi.com", "graph.microsoft.com", "onedrive.live.com", "sharepoint.com",
               "blob.core.windows.net", "box.com", "pastebin.com", "gist.githubusercontent.com",
               "transfer.sh", "0x0.st", "file.io")),
    (DEV, ("github.com", "api.github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
           "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io", "rubygems.org",
           "proxy.golang.org", "nuget.org")),
)

_PATHS = (
    (TELEMETRY, re.compile(r"event_logging|telemetry|/metrics?\b|analytics|/track\b|/collect\b|"
                           r"/v1/(traces|logs)\b|/rgstr|/initialize\b|/log_event|/statsig|"
                           r"/ces/|clearcut|/usage[-_]?(stats|report)", re.I)),
    (ERRORS, re.compile(r"/envelope/|/store/|crash|error[-_]?report", re.I)),
    (AUTH, re.compile(r"/oauth|/auth\b|/token\b|/login|/userinfo|/account|/organizations/", re.I)),
    (TOOLS, re.compile(r"/mcp|mcp[-_]registry|/plugins?/|/extensions?/", re.I)),
    (STORAGE, re.compile(r"/upload|/files\b", re.I)),
)


def _host_match(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def categorize(host: str, path: str) -> str:
    host = (host or "").lower().rstrip(".")
    path = (path or "").split("?", 1)[0]
    for category, suffixes in _HOSTS:
        if any(_host_match(host, s) for s in suffixes):
            return category
    llm = is_llm_host(host)
    for category, pattern in _PATHS:
        if pattern.search(path):
            # A file upload to an LLM API (OpenAI /v1/files, Gemini /upload) is model input.
            if category == STORAGE and llm:
                return LLM
            return category
    return LLM if llm else OTHER


def sort_key(category: str) -> Tuple[int, str]:
    return (ORDER.index(category) if category in ORDER else len(ORDER), category)


def describe(category: Optional[str]) -> str:
    return DESCRIPTIONS.get(category or OTHER, "")
