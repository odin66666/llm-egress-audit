"""Command line interface: llm-egress-audit <command>"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import __version__, config
from .categories import describe, sort_key
from .store import KeyMismatch, Store
from .verify import GRADES, Report, iter_files, verify_file

DEFAULT_PORT = 8765
EXIT_ERROR = 64


def _ts(ts: Optional[float]) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


def _proxy_url(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def _proxy_env(port: int) -> dict:
    ca = str(config.mitm_ca_cert())
    url = _proxy_url(port)
    return {
        "HTTPS_PROXY": url, "HTTP_PROXY": url, "https_proxy": url, "http_proxy": url,
        "ALL_PROXY": url, "NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
        "NODE_USE_ENV_PROXY": "1",          # Node >= 24 built-in fetch honours HTTPS_PROXY
        "NODE_EXTRA_CA_CERTS": ca,          # Node: adds the mitmproxy CA to the defaults
        "SSL_CERT_FILE": ca, "REQUESTS_CA_BUNDLE": ca, "CURL_CA_BUNDLE": ca,
    }


def _proxy_alive(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


# -- commands --------------------------------------------------------------

def cmd_init(args) -> int:
    store = Store.open_default()
    store.close()
    print(f"data directory : {config.home()}")
    print(f"key            : {config.key_path()}  (back it up: without it the log is unreadable)")
    print(f"mitmproxy CA   : {config.mitm_ca_cert()}"
          + ("" if config.mitm_ca_cert().exists() else "  (created on the first `run`)"))
    return 0


def cmd_run(args) -> int:
    # Prefer the mitmdump installed alongside this interpreter (an unactivated venv).
    mitmdump = (shutil.which("mitmdump", path=str(Path(sys.executable).parent))
                or shutil.which("mitmdump"))
    if not mitmdump:
        print("mitmdump not found. Install the proxy extra: pip install 'llm-egress-audit[proxy]'",
              file=sys.stderr)
        return EXIT_ERROR
    if _proxy_alive(args.port):
        print(f"port {args.port} is already in use", file=sys.stderr)
        return EXIT_ERROR
    Store.open_default().close()      # fail now, not inside mitmdump, if the key is wrong
    addon = Path(__file__).with_name("addon.py")
    cmd = [mitmdump, "--listen-host", "127.0.0.1", "--listen-port", str(args.port),
           "-s", str(addon), "--set", "flow_detail=0", "-q", *args.mitm_args]
    env = dict(os.environ)
    if args.no_guard:
        env["LLM_EGRESS_AUDIT_GUARD"] = "0"
        print("guard DISABLED: protected content will be recorded, not blocked")
    print(f"recording egress on {_proxy_url(args.port)} -> {config.db_path()}")
    print("start agents with:  llm-egress-audit exec -- <command>   (Ctrl+C to stop)")
    try:
        return subprocess.call(cmd, env=env)
    except KeyboardInterrupt:
        return 0


def cmd_exec(args) -> int:
    if not args.command:
        print("usage: llm-egress-audit exec -- <command> [args...]", file=sys.stderr)
        return EXIT_ERROR
    # Fail closed: an agent started without the proxy would look monitored and not be.
    if not _proxy_alive(args.port):
        print(f"no proxy on port {args.port}: start `llm-egress-audit run` first. "
              "Refusing to launch unmonitored.", file=sys.stderr)
        return EXIT_ERROR
    if not config.mitm_ca_cert().exists():
        print(f"mitmproxy CA not found at {config.mitm_ca_cert()}", file=sys.stderr)
        return EXIT_ERROR
    env = dict(os.environ, **_proxy_env(args.port))
    exe = shutil.which(args.command[0]) or args.command[0]
    try:
        return subprocess.call([exe, *args.command[1:]], env=env)
    except KeyboardInterrupt:
        return 130


def cmd_env(args) -> int:
    env = _proxy_env(args.port)
    for k, v in env.items():
        if args.shell == "powershell":
            print(f"$env:{k} = '{v}'")
        elif args.shell == "cmd":
            print(f"set {k}={v}")
        else:
            print(f"export {k}='{v}'")
    return 0


def _print_report(r: Report) -> None:
    print(r.file)
    conf = f" ({r.confidence} evidence)" if r.grade >= 3 else ""
    print(f"  grade {r.grade}/4  {r.label}{conf}")
    if r.total:
        what = "text fingerprints" if r.kind != "binary" else "4 KiB chunks"
        line = f"  content: {r.coverage:.1%} of {r.total} {what} seen leaving"
        if r.whole_file_seen:
            line += " + the whole file byte-identical"
        print(line)
    elif r.whole_file_seen:
        print("  content: the whole file was sent byte-identical")
    if r.exposed_lines:
        spans = ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in r.exposed_lines[:12])
        more = f" (+{len(r.exposed_lines) - 12} more ranges)" if len(r.exposed_lines) > 12 else ""
        print(f"  lines  : {spans}{more}")
    if r.categories:
        print(f"  went to: {', '.join(r.categories)}")
    for title, items in (("content sent to", r.content_sent_to), ("name sent to", r.name_sent_to)):
        if items:
            print(f"  {title}:")
            for e in sorted(items, key=lambda e: (sort_key(e.category), e.first_ts)):
                print(f"    [{e.category}] {e.host}  first {_ts(e.first_ts)}  {e.method} {e.path}")
                if e.client:
                    print(f"          client: {e.client}")
    if r.blocked:
        first, last = r.blocked[0]["ts"], r.blocked[-1]["ts"]
        print(f"  blocked: {len(r.blocked)} attempt(s), {_ts(first)} -> {_ts(last)}")
        by_client: dict = {}
        for b in r.blocked:
            by_client.setdefault(b["tool"], []).append(b)
        for client, items in by_client.items():
            print(f"    {len(items):>4} x {client}")
            print(f"           last: {items[-1]['detail']}")
    for n in r.notes:
        print(f"  note   : {n}")


def cmd_verify(args) -> int:
    store = Store.open_default()
    try:
        reports = []
        for path in iter_files(args.paths):
            try:
                reports.append(verify_file(store, path))
            except OSError as exc:
                print(f"{path}: {exc}", file=sys.stderr)
        first, last, n, bad = store.window()
    finally:
        store.close()
    if args.min_grade:
        shown = [r for r in reports if r.grade >= args.min_grade]
    else:
        shown = reports
    window = {"first": first, "last": last, "requests": n, "unanalysed_requests": bad}
    if args.json:
        print(json.dumps({"window": window, "files": [r.to_dict() for r in shown]}, indent=2))
    else:
        for r in shown:
            _print_report(r)
            print()
        counts = {g: sum(1 for r in reports if r.grade == g) for g in GRADES}
        print("summary: " + "  ".join(f"{GRADES[g].lower()} {c}" for g, c in counts.items() if c))
        by_cat: dict = {}
        for r in reports:
            for c in r.categories:
                by_cat[c] = by_cat.get(c, 0) + 1
        if by_cat:
            print("content found in: " + "  ".join(
                f"{c} {by_cat[c]} file(s)" for c in sorted(by_cat, key=sort_key)))
        print(f"window : {_ts(first)} -> {_ts(last)}  ({n} requests recorded"
              + (f", {bad} could not be analysed" if bad else "") + ")")
        print("         grade 0 means 'not seen in this window through this proxy', "
              "not 'never sent'.")
    return max((r.grade for r in reports), default=0)


def cmd_stats(args) -> int:
    store = Store.open_default()
    try:
        first, last, n, bad = store.window()
        dests = store.destinations()
    finally:
        store.close()
    print(f"window: {_ts(first)} -> {_ts(last)}  {n} requests, {bad} not analysed")
    groups: dict = {}
    for row in dests:
        groups.setdefault(row[2], []).append(row)
    for category in sorted(groups, key=sort_key):
        rows = groups[category]
        print()
        print(f"{category}  ({describe(category)}) - {sum(r[5] for r in rows)} requests")
        for host, client, _, f, l, count in rows:
            print(f"  {count:>7}  {host}  {_ts(f)} -> {_ts(l)}  {client[:60]}")
    return 0


WORDS = ("amber", "basalt", "cobalt", "delta", "ember", "fjord", "garnet", "harbor", "indigo",
         "juniper", "kelp", "lumen", "marble", "nectar", "onyx", "pollen", "quartz", "raven",
         "saffron", "tundra", "umber", "velvet", "willow", "xenon", "yarrow", "zephyr")


def cmd_canary(args) -> int:
    path = Path(args.path)
    if path.exists():
        print(f"{path} already exists", file=sys.stderr)
        return EXIT_ERROR
    words = [secrets.choice(WORDS) + str(secrets.randbelow(1000)) for _ in range(60)]
    body = "\n".join(" ".join(words[i:i + 10]) for i in range(0, 60, 10))
    # No fixed header: shared words across canaries would make them match each other.
    path.write_text(f"canary {secrets.token_hex(4)}\n" + body + "\n", encoding="utf-8")
    print(f"wrote {path}")
    print("Ask an agent (started through the proxy) to read it, then run:")
    print(f"  llm-egress-audit verify {path}")
    print("Grade 4 proves the pipeline sees that agent. Grade 0 means it bypasses the proxy.")
    return 0


def cmd_protect(args) -> int:
    from .guard import expand

    store = Store.open_default()
    try:
        for p in args.paths:
            path = Path(p).expanduser().resolve()
            if not path.exists():
                print(f"{path}: does not exist (protected anyway, in case it appears later)")
            added = store.protect(str(path))
            files = expand([str(path)])
            print(f"{'protected' if added else 'already protected'}: {path}  ({len(files)} file(s))")
    finally:
        store.close()
    if _proxy_alive(args.port):
        print("a running proxy picks this up within 15 seconds")
    return 0


def cmd_unprotect(args) -> int:
    store = Store.open_default()
    try:
        for p in args.paths:
            path = str(Path(p).expanduser().resolve())
            print(f"{'unprotected' if store.unprotect(path) else 'was not protected'}: {path}")
    finally:
        store.close()
    return 0


def cmd_protected(args) -> int:
    from .guard import expand

    store = Store.open_default()
    try:
        roots = store.protected()
    finally:
        store.close()
    if not roots:
        print("nothing protected. Add with: llm-egress-audit protect <file|folder>")
    for root in roots:
        n = len(expand([root])) if Path(root).exists() else 0
        state = "" if Path(root).exists() else "  (missing)"
        print(f"{n:>6} file(s)  {root}{state}")
    return 0


def cmd_log_block(args) -> int:
    store = Store.open_default()
    try:
        store.log_block(args.tool, str(Path(args.path).resolve()), args.detail or "")
    finally:
        store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-egress-audit",
        description="Record what leaves your machine towards LLM APIs, and tell whether a "
                    "given file was sent: not at all, name only, partially or in full.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create key and database, show paths").set_defaults(fn=cmd_init)

    r = sub.add_parser("run", help="start the recording proxy (mitmdump)")
    r.add_argument("--port", type=int, default=DEFAULT_PORT)
    r.add_argument("--no-guard", action="store_true",
                   help="record protected content instead of blocking it")
    r.add_argument("mitm_args", nargs=argparse.REMAINDER, help="extra args after -- go to mitmdump")
    r.set_defaults(fn=cmd_run)

    e = sub.add_parser("exec", help="run a command with its traffic routed through the proxy")
    e.add_argument("--port", type=int, default=DEFAULT_PORT)
    e.add_argument("command", nargs=argparse.REMAINDER)
    e.set_defaults(fn=cmd_exec)

    v = sub.add_parser("env", help="print proxy variables for a shell")
    v.add_argument("--port", type=int, default=DEFAULT_PORT)
    v.add_argument("--shell", choices=("bash", "powershell", "cmd"),
                   default="powershell" if sys.platform == "win32" else "bash")
    v.set_defaults(fn=cmd_env)

    f = sub.add_parser("verify", help="grade the exposure of files or folders (exit code = max grade)")
    f.add_argument("paths", nargs="+")
    f.add_argument("--json", action="store_true")
    f.add_argument("--min-grade", type=int, default=0, help="only show files at or above this grade")
    f.set_defaults(fn=cmd_verify)

    sub.add_parser("stats", help="observation window and destinations").set_defaults(fn=cmd_stats)

    c = sub.add_parser("canary", help="write a random-text file to test that an agent is monitored")
    c.add_argument("path")
    c.set_defaults(fn=cmd_canary)

    pr = sub.add_parser("protect", help="block any request carrying content from these files/folders")
    pr.add_argument("paths", nargs="+")
    pr.add_argument("--port", type=int, default=DEFAULT_PORT)
    pr.set_defaults(fn=cmd_protect)

    up = sub.add_parser("unprotect", help="stop protecting files/folders")
    up.add_argument("paths", nargs="+")
    up.set_defaults(fn=cmd_unprotect)

    sub.add_parser("protected", help="list protected paths").set_defaults(fn=cmd_protected)

    b = sub.add_parser("log-block", help="record a blocked access (for agent hooks)")
    b.add_argument("--tool", required=True)
    b.add_argument("--path", required=True)
    b.add_argument("--detail")
    b.set_defaults(fn=cmd_log_block)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    for attr in ("command", "mitm_args"):
        rest = getattr(args, attr, None)
        if rest and rest[0] == "--":
            setattr(args, attr, rest[1:])
    try:
        return args.fn(args)
    except KeyMismatch as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
