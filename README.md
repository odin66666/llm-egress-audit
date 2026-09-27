# llm-egress-audit

**Know whether a file really left your machine — and how much of it. Or stop it from leaving.**

You tell an AI agent *"don't read that file"* or *"read it but don't send it anywhere"*.
The agent says *"OK, I ignored it"*. Is that true?

You cannot answer that by asking the model: its answer is exactly the thing you are
trying to check. And "read locally, don't send" does not exist for cloud models — the
model runs on the provider's servers, so whatever an agent reads goes into the next
request.

`llm-egress-audit` answers from the only place that cannot lie about it: **the network**.
It sits between your agents and the internet, fingerprints everything they send, and
later tells you, for any file:

| Grade | Label | Meaning |
|---|---|---|
| 0 | NOT SEEN | nothing from this file left through the proxy |
| 1 | BLOCKED | an agent tried and was stopped locally (guard mode, or an agent hook) |
| 2 | NAME ONLY | only the file name left (directory listings, git status, prompts) |
| 3 | PARTIAL | part of the content left — with the percentage and the line ranges |
| 4 | FULL | the whole content left (≥ 90 %, or the file byte-identical) |

…plus **when**, **to which host**, **by which client**, and **what kind of destination**:

| Category | What it is |
|---|---|
| `llm` | a prompt sent to a model |
| `telemetry` | usage analytics, metrics, logs (Datadog, Statsig, Segment, an agent's own event log…) |
| `error-reporting` | crash and error reports (Sentry, Bugsnag…) |
| `cloud-storage` | file storage, uploads, paste sites |
| `web/search` | web search and page fetch services |
| `tools/mcp` | tool integrations, MCP servers and registries |
| `dev-services` | code hosting and package registries |
| `auth` | login, tokens, account data |
| `other` | everything else — still recorded, still verifiable |

The category comes from host **and** path, because one host often does several jobs:
`api.anthropic.com` answers prompts on `/v1/messages` and collects telemetry on
`/api/event_logging`. Content that reaches two categories is reported under both, with
the first time for each.

So this is not only about LLMs: anything a monitored process sends anywhere is covered.

It works with any agent or tool that can use an HTTPS proxy — Claude Code, Codex,
Gemini CLI, Aider, scripts using the OpenAI/Anthropic SDKs, curl — because it does not
depend on the agent's cooperation or on its logs.

```
$ llm-egress-audit verify notes/contract-draft.txt
notes/contract-draft.txt
  grade 3/4  PARTIAL (strong evidence)
  content: 41.3% of 812 text fingerprints seen leaving
  lines  : 1-38, 120-151
  went to: llm
  content sent to:
    [llm] api.anthropic.com  first 2026-09-27 18:44:20  POST /v1/messages
          client: claude-cli/2.1.283 (external, sdk-cli)

summary: partial 1
content found in: llm 1 file(s)
window : 2026-09-27 09:02:11 -> 2026-09-27 18:44:22  (4312 requests recorded)
         grade 0 means 'not seen in this window through this proxy', not 'never sent'.
```

## How it works

1. **`run`** starts a local [mitmproxy](https://mitmproxy.org) on `127.0.0.1` with a small addon.
2. **`exec -- <agent>`** launches the agent with `HTTPS_PROXY` and the proxy's CA set only for
   that process. There is nothing to install in the system trust store. If the proxy is not running,
   `exec` **refuses to launch**, so an agent never looks monitored when it is not.
3. For every outgoing request body and WebSocket message, the addon:
   - parses JSON (escaping disappears), NDJSON, form data and multipart uploads, including
     JSON nested inside JSON strings (Codex encodes tool output twice);
   - decodes base64 and `data:` URLs (attached documents and images);
   - strips line-number prefixes that agents add when they read files (`   12\t…`, `12→…`);
   - splits text into overlapping **8-word windows** after normalising case and whitespace;
   - stores for each window, file name and binary chunk only a **truncated HMAC-SHA256
     under a local secret key**, with the destination and the first request it was seen in.
4. **`verify <file|folder>`** computes the same fingerprints for your file and looks them up.

### The log is not a second leak

No traffic content is ever written: no bodies, no headers, no API keys, no query strings (query
*values* are fingerprinted, then dropped). What a stolen database does reveal is
**metadata**: which hosts were contacted, by which clients, when, on which URL paths, and
which paths you protect. The content side is a list of random 64-bit integers. With the key as well, an attacker can only *confirm a guess* ("did this exact
text leave?"), not recover content. Keep the key somewhere else with
`LLM_EGRESS_AUDIT_KEYFILE` if that matters to you.

Because fingerprints are computed for *everything* that leaves, verification is
**retroactive**: you do not have to declare sensitive files in advance.

## Install

```bash
pip install "llm-egress-audit[proxy]"        # add ,pdf for PDF text matching
```

Python ≥ 3.9. The core has no dependencies; `[proxy]` pulls mitmproxy, `[pdf]` pulls pypdf.

## Quick start

```bash
# terminal 1: start recording
llm-egress-audit run

# terminal 2: prove that your agent is really seen
llm-egress-audit canary canary.txt
llm-egress-audit exec -- claude -p "Read canary.txt and tell me how many lines it has"
llm-egress-audit verify canary.txt          # expect grade 4

# from now on, start agents through exec
llm-egress-audit exec -- codex
llm-egress-audit exec -- gemini
llm-egress-audit exec -- aider

# any time later
llm-egress-audit verify ~/Documents/private      # whole folders work
llm-egress-audit verify --json secret.pdf        # machine-readable
llm-egress-audit stats                           # window and destinations
```

To route a whole shell rather than a single command:

```bash
eval "$(llm-egress-audit env --shell bash)"          # bash/zsh
llm-egress-audit env --shell powershell | iex         # PowerShell
```

## Guard mode: keep files on your machine

Recording tells you afterwards. Guard mode stops the request before it leaves:

```bash
llm-egress-audit protect ~/Documents/contracts ~/notes/health.md
llm-egress-audit protected                     # list
llm-egress-audit unprotect ~/notes/health.md
```

Every request is checked **before** it is forwarded. If it carries content from a
protected file, it is not sent: HTTP requests get a local `403` with an
`egress_blocked` error, WebSocket messages are dropped and the socket is closed. The
attempt is logged, and `verify` reports it as grade 1.

- **No agent cooperation needed.** It does not matter whether the agent promised not to
  send the file, or which route it takes. In testing, Codex retried five times over
  WebSocket, then fell back by itself to plain HTTPS; every attempt was stopped.
- **Fails closed.** If the check itself errors, the request is blocked.
- **The error an agent sees is generic** and never names the file: agents sometimes
  paste error text into their next prompt, and a file name is information too.
- **A blocked session is stuck, by design.** Once an agent has read a protected file,
  the content is in its conversation context and goes out with every later request.
  Start a new session.
- Folders are rescanned every 15 seconds, so edits and new files are picked up while
  the proxy runs; `protect` on a running proxy takes effect within that time.
- `run --no-guard` records protected content instead of blocking it.

⚠️ **What guard mode is not.** It blocks *fragments of documents*: a request is stopped
when it carries at least three 8-word windows of a protected file, which is roughly
ten consecutive words (fewer for tiny files). A single short value copied out of a file,
such as a password, an IBAN or an API key, is below that threshold and **passes**. For
short secrets, use a secret scanner; this tool protects documents.

The list of protected **paths** is stored in the database, because the guard must
re-read them. Their content never is.

### Always run the canary first

A tool that bypasses the proxy produces **grade 0 for everything**, and that looks
exactly like good news. `canary` writes a file of random words that exists nowhere
else. Have the agent read it: if `verify` does not say grade 4, that agent is not
being observed and none of its grade 0s mean anything.

## Exit codes

`verify` exits with the **highest grade found** (0–4), so it can gate scripts and CI:

```bash
llm-egress-audit verify secrets/ || echo "something in secrets/ left the machine"
```

`64` means a usage or configuration error.

## Hooks: recording blocked attempts (grade 1)

Guard mode writes grade 1 by itself. Agent-side guards (hooks, ignore files) can
report their own denials too:

```bash
llm-egress-audit log-block --tool claude-code --path /home/me/secret.txt --detail "PreToolUse deny"
```

Ready-made adapters (Claude Code hooks, `.cursorignore`, `.aiderignore`, Codex and
Gemini CLI configuration) are planned for v0.2.

## Tested

| Client | Result |
|---|---|
| Claude Code 2.1.283, Windows 11 (`exec -- claude -p …`) | grade 4 on the canary it read, grade 0 on the one it did not |
| Codex CLI 0.153.4, Windows 11 (`exec -- codex exec …`), WebSocket transport | asked to *count the lines*, it ran `(Get-Content f).Count` locally and only the number left: **grade 2, correctly**. Asked to *show the content*: grade 4 |
| Python `urllib` → `api.anthropic.com` | grade 4 |

With guard mode on and the canary protected, both agents were stopped: Claude Code on
its first request (it shows the error prefixed with *"Failed to authenticate"*, because
it reads every 403 that way), Codex after trying WebSocket and then HTTPS. Coverage
stayed at 0 %, and 15 blocked attempts were logged. An unprotected file read in the same
run went through normally.

The Codex case is the point of the tool: "the agent read the file" and "the file left
the machine" are different facts, and only the second one is measured.

Other clients should work if they honour `HTTPS_PROXY` and a custom CA. Please open an
issue with the result of the canary test for your agent, whether it passes or fails.

## Limits

These are part of the tool's contract, not small print.

- **It proves what left your machine, nothing more.** What the provider keeps, logs or
  trains on is outside what any local tool can see.
- **Only traffic that goes through the proxy is observed.** Apps that ignore proxy
  settings, pin certificates or run their own network stack (some desktop apps and IDEs)
  are invisible. The canary test is how you find out.
- **Grade 0 is bounded by the observation window.** Anything sent before `run`, or through
  another route, is unknown. The report prints the window every time.
- **Transformed content is not matched.** A summary or translation written by the agent,
  an image it resized, or a PDF re-rendered by the client produce different bytes. Raw
  reads, which are how agents read files, are matched.
- **Short texts (< 8 words)** are matched only when sent as a whole string on their own.
- **Common phrases can match by coincidence.** Isolated matches are reported as `weak
  evidence`. A name-only match may come from a different file with the same name.
- **Losing the key makes the log unreadable.** `init` shows where it is; back it up.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LLM_EGRESS_AUDIT_HOME` | per-user data dir (`%LOCALAPPDATA%\llm-egress-audit`, `~/Library/Application Support/…`, `~/.local/share/…`) | database location |
| `LLM_EGRESS_AUDIT_KEYFILE` | `$HOME/key` | HMAC key location |
| `LLM_EGRESS_AUDIT_LLM_HOSTS` | — | extra hosts, comma-separated, to classify as `llm` (for example your own gateway) |
| `MITMPROXY_CONFDIR` | `~/.mitmproxy` | where the proxy CA is read from |

Every destination is recorded, not only known LLM hosts: agents also send telemetry and
error reports, and those can carry content too. `stats` lists them all.

## Development

```bash
pip install -e ".[proxy,pdf]"
python -m unittest discover -s tests
```

## License

MIT
