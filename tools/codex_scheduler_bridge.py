#!/usr/bin/env python3
"""Local Codex scheduler bridge for public-safe improvement runs.

This is not the upstream paperclipai/paperclip server. It is a small helper for
running Codex against this repo when Paperclip or another orchestrator triggers it.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = REPO_ROOT / ".paperclip"
RUNS_DIR = STATE_DIR / "runs"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def env_bool(key: str, default: bool = False) -> bool:
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(key: str, default: int) -> int:
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def run_command(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def git_output(*args: str, timeout: int = 60) -> str:
    result = run_command(["git", *args], timeout)
    return result.stdout.strip()


@dataclass
class ServerConfig:
    host: str = os.environ.get("CODEX_SCHEDULER_HOST", "0.0.0.0")
    port: int = env_int("CODEX_SCHEDULER_PORT", 8090)
    schedule_seconds: int = env_int("CODEX_SCHEDULER_SCHEDULE_SECONDS", 0)
    codex_enabled: bool = env_bool("CODEX_SCHEDULER_CODEX_ENABLED", True)
    autocheck: bool = env_bool("CODEX_SCHEDULER_AUTOCHECK", True)
    autocommit: bool = env_bool("CODEX_SCHEDULER_AUTOCOMMIT", False)
    autopush: bool = env_bool("CODEX_SCHEDULER_AUTOPUSH", False)
    allow_dirty: bool = env_bool("CODEX_SCHEDULER_ALLOW_DIRTY", False)
    command_timeout_seconds: int = env_int("CODEX_SCHEDULER_COMMAND_TIMEOUT_SECONDS", 1800)
    codex_prompt: str = os.environ.get(
        "CODEX_SCHEDULER_CODEX_PROMPT",
        "Improve this public R&D lab repo in a small, safe, well-tested way. "
        "Do not add secrets, private topology, credentials, or operational runbooks. "
        "Prefer documentation, tests, local scaffolding, and public-safe automation.",
    )
    commit_message: str = os.environ.get(
        "CODEX_SCHEDULER_COMMIT_MESSAGE",
        "chore: apply scheduled codex improvement",
    )


@dataclass
class RunRecord:
    run_id: str
    status: str
    started_at: str
    finished_at: str | None = None
    reason: str | None = None
    command: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    check_status: int | None = None
    commit: str | None = None
    pushed: bool = False
    error: str | None = None
    artifacts: dict[str, str] = field(default_factory=dict)


class PaperclipScheduler:
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.lock = threading.Lock()
        self.runs: list[RunRecord] = []
        self.active = False
        RUNS_DIR.mkdir(parents=True, exist_ok=True)

    def trigger(self, reason: str = "manual") -> RunRecord:
        with self.lock:
            if self.active:
                record = RunRecord(
                    run_id=str(uuid.uuid4()),
                    status="rejected",
                    started_at=utc_now(),
                    finished_at=utc_now(),
                    reason=reason,
                    error="another run is active",
                )
                self._remember(record)
                return record
            self.active = True

        record = RunRecord(
            run_id=str(uuid.uuid4()),
            status="running",
            started_at=utc_now(),
            reason=reason,
        )
        self._remember(record)
        threading.Thread(target=self._run, args=(record,), daemon=True).start()
        return record

    def _run(self, record: RunRecord) -> None:
        run_dir = RUNS_DIR / record.run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        try:
            if not self.config.codex_enabled:
                raise RuntimeError("CODEX_SCHEDULER_CODEX_ENABLED is false")

            before_status = git_output("status", "--porcelain")
            if before_status and not self.config.allow_dirty:
                raise RuntimeError(
                    "worktree is dirty; set CODEX_SCHEDULER_ALLOW_DIRTY=true only when intentional"
                )

            command = ["codex", "--yolo", self.config.codex_prompt]
            record.command = command
            self._write_text(run_dir / "command.txt", shlex.join(command))

            codex_result = run_command(command, self.config.command_timeout_seconds)
            self._write_text(run_dir / "codex.stdout.log", codex_result.stdout)
            self._write_text(run_dir / "codex.stderr.log", codex_result.stderr)
            if codex_result.returncode != 0:
                raise RuntimeError(f"codex exited with status {codex_result.returncode}")

            if self.config.autocheck:
                check_result = run_command(["make", "check"], self.config.command_timeout_seconds)
                record.check_status = check_result.returncode
                self._write_text(run_dir / "check.stdout.log", check_result.stdout)
                self._write_text(run_dir / "check.stderr.log", check_result.stderr)
                if check_result.returncode != 0:
                    raise RuntimeError("make check failed")

            changed = git_output("status", "--porcelain")
            record.changed_files = [
                line[3:] if len(line) > 3 else line for line in changed.splitlines() if line
            ]

            self._write_text(run_dir / "git-status.txt", changed)
            self._write_text(run_dir / "git-diff.patch", git_output("diff", "--patch", timeout=120))

            if record.changed_files and self.config.autocommit:
                run_command(["git", "add", "--all"], 120)
                commit = run_command(["git", "commit", "-m", self.config.commit_message], 120)
                self._write_text(run_dir / "commit.stdout.log", commit.stdout)
                self._write_text(run_dir / "commit.stderr.log", commit.stderr)
                if commit.returncode != 0:
                    raise RuntimeError("git commit failed")
                record.commit = git_output("rev-parse", "HEAD")

                if self.config.autopush:
                    push = run_command(["git", "push"], 300)
                    self._write_text(run_dir / "push.stdout.log", push.stdout)
                    self._write_text(run_dir / "push.stderr.log", push.stderr)
                    if push.returncode != 0:
                        raise RuntimeError("git push failed")
                    record.pushed = True

            record.status = "completed"
        except Exception as exc:
            record.status = "failed"
            record.error = str(exc)
        finally:
            record.finished_at = utc_now()
            record.artifacts = {
                "run_dir": str(run_dir.relative_to(REPO_ROOT)),
                "record": str((run_dir / "record.json").relative_to(REPO_ROOT)),
            }
            self._write_json(run_dir / "record.json", asdict(record))
            with self.lock:
                self.active = False

    def _remember(self, record: RunRecord) -> None:
        self.runs.insert(0, record)
        del self.runs[100:]

    def _write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def scheduler_loop(self) -> None:
        if self.config.schedule_seconds <= 0:
            return
        while True:
            time.sleep(self.config.schedule_seconds)
            self.trigger("scheduled")


def make_handler(scheduler: PaperclipScheduler, config: ServerConfig) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self) -> None:
            if self.path in {"/", "/index.html", "/health", "/config", "/runs"}:
                self.send_response(200)
                content_type = (
                    "text/html; charset=utf-8"
                    if self.path in {"/", "/index.html"}
                    else "application/json"
                )
                self.send_header("Content-Type", content_type)
                self.end_headers()
            else:
                self.send_error(404)

        def do_GET(self) -> None:
            if self.path in {"/", "/index.html"}:
                self._html(render_dashboard(scheduler, config))
            elif self.path == "/health":
                self._json({"status": "ok", "service": "codex-scheduler-bridge"})
            elif self.path == "/config":
                payload = asdict(config)
                payload["codex_prompt"] = "[redacted from config endpoint]"
                self._json(payload)
            elif self.path == "/runs":
                self._json([asdict(run) for run in scheduler.runs])
            else:
                self.send_error(404)

        def do_POST(self) -> None:
            if self.path != "/runs":
                self.send_error(404)
                return
            record = scheduler.trigger("manual")
            status = 202 if record.status == "running" else 409
            self._json(asdict(record), status=status)

        def log_message(self, format: str, *args: Any) -> None:
            print(f"{self.address_string()} - {format % args}")

        def _json(self, payload: Any, status: int = 200) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, content: str, status: int = 200) -> None:
            body = content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def render_dashboard(scheduler: PaperclipScheduler, config: ServerConfig) -> str:
    runs = [asdict(run) for run in scheduler.runs[:20]]
    run_rows = "\n".join(render_run_row(run) for run in runs)
    if not run_rows:
        run_rows = '<tr><td colspan="7" class="muted">No runs recorded yet.</td></tr>'

    autocommit = "enabled" if config.autocommit else "disabled"
    autopush = "enabled" if config.autopush else "disabled"
    schedule = (
        f"every {config.schedule_seconds}s" if config.schedule_seconds > 0 else "manual only"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Project Athernex Codex Scheduler Bridge</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0f1419;
      --panel: #161d24;
      --border: #2a3440;
      --text: #e8edf2;
      --muted: #9aa8b5;
      --accent: #4ea1ff;
      --danger: #ff6b6b;
      --ok: #6bd68a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px;
    }}
    header {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 24px;
    }}
    h1 {{ margin: 0 0 6px; font-size: 28px; }}
    h2 {{ margin: 0 0 14px; font-size: 18px; }}
    p {{ margin: 0; color: var(--muted); }}
    button {{
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #06111d;
      cursor: pointer;
      font-weight: 700;
      padding: 10px 14px;
    }}
    button:disabled {{ cursor: wait; opacity: .7; }}
    section {{
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--panel);
      margin-top: 16px;
      padding: 18px;
    }}
    .grid {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    }}
    .metric {{
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
    }}
    .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .value {{ font-size: 16px; margin-top: 5px; word-break: break-word; }}
    .muted {{ color: var(--muted); }}
    .ok {{ color: var(--ok); }}
    .danger {{ color: var(--danger); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid var(--border);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    code {{
      color: #b9d8ff;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
    }}
    @media (max-width: 760px) {{
      header {{ display: block; }}
      button {{ margin-top: 16px; width: 100%; }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Project Athernex Codex Scheduler Bridge</h1>
        <p>Local control surface for scheduled public-safe <code>codex --yolo</code> improvement runs.</p>
      </div>
      <button id="trigger">Run Codex Now</button>
    </header>

    <section>
      <h2>Status</h2>
      <div class="grid">
        <div class="metric"><div class="label">Bind</div><div class="value"><code>{escape(config.host)}:{config.port}</code></div></div>
        <div class="metric"><div class="label">Schedule</div><div class="value">{escape(schedule)}</div></div>
        <div class="metric"><div class="label">Autocommit</div><div class="value">{escape(autocommit)}</div></div>
        <div class="metric"><div class="label">Autopush</div><div class="value">{escape(autopush)}</div></div>
        <div class="metric"><div class="label">Worktree Policy</div><div class="value">allow dirty: {str(config.allow_dirty).lower()}</div></div>
        <div class="metric"><div class="label">Evidence</div><div class="value"><code>.paperclip/runs</code></div></div>
      </div>
    </section>

    <section>
      <h2>Recent Runs</h2>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Reason</th>
            <th>Started</th>
            <th>Finished</th>
            <th>Changed Files</th>
            <th>Commit</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>{run_rows}</tbody>
      </table>
    </section>
  </main>
  <script>
    const trigger = document.getElementById('trigger');
    trigger.addEventListener('click', async () => {{
      trigger.disabled = true;
      trigger.textContent = 'Starting...';
      try {{
        const response = await fetch('/runs', {{ method: 'POST' }});
        if (!response.ok) {{
          const body = await response.text();
          alert('Run was not started: ' + body);
        }}
        window.location.reload();
      }} catch (error) {{
        alert('Request failed: ' + error);
      }} finally {{
        trigger.disabled = false;
        trigger.textContent = 'Run Codex Now';
      }}
    }});
    setTimeout(() => window.location.reload(), 15000);
  </script>
</body>
</html>"""


def render_run_row(run: dict[str, Any]) -> str:
    changed_files = run.get("changed_files") or []
    changed = "<br>".join(f"<code>{escape(path)}</code>" for path in changed_files[:8])
    if len(changed_files) > 8:
        changed += f"<br><span class=\"muted\">+{len(changed_files) - 8} more</span>"
    if not changed:
        changed = '<span class="muted">none</span>'

    status = escape(str(run.get("status", "unknown")))
    status_class = "ok" if status == "completed" else "danger" if status == "failed" else ""
    commit = run.get("commit") or ""
    commit_text = f"<code>{escape(commit[:12])}</code>" if commit else '<span class="muted">none</span>'
    error = run.get("error") or ""
    error_text = escape(error) if error else '<span class="muted">none</span>'

    return f"""<tr>
      <td class="{status_class}">{status}</td>
      <td>{escape(str(run.get("reason") or ""))}</td>
      <td>{escape(str(run.get("started_at") or ""))}</td>
      <td>{escape(str(run.get("finished_at") or ""))}</td>
      <td>{changed}</td>
      <td>{commit_text}</td>
      <td>{error_text}</td>
    </tr>"""


def main() -> None:
    config = ServerConfig()
    scheduler = PaperclipScheduler(config)
    threading.Thread(target=scheduler.scheduler_loop, daemon=True).start()
    server = ThreadingHTTPServer((config.host, config.port), make_handler(scheduler, config))
    print(f"codex scheduler bridge listening on http://{config.host}:{config.port}")
    print(f"repo_root={REPO_ROOT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
