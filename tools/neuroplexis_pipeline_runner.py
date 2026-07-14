#!/usr/bin/env python3
"""Config-driven Neuroplexis pipeline runner for bounded Codex tasks."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SECRET_ASSIGNMENT = re.compile(
    r"(?P<key>api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|secret|password|passwd|private[_-]?key)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\"'\s#]{8,})",
    re.I,
)
PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA |)?PRIVATE KEY-----", re.I)
PLACEHOLDERS = {
    "replace-me",
    "replace-me-locally",
    "changeme",
    "change-me",
    "dummy",
    "example",
    "placeholder",
}


@dataclass
class PipelineContext:
    config: dict[str, Any]
    repo_root: Path
    run_dir: Path
    branch_name: str
    dry_run: bool


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(
    args: list[str],
    cwd: Path,
    timeout: int = 1800,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{result.stderr}"
        )
    return result


def write_log(ctx: PipelineContext, message: str) -> None:
    line = f"[{datetime.now(timezone.utc).isoformat()}] {message}"
    print(line)
    with (ctx.run_dir / "pipeline.log").open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned[:48] or "pipeline"


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def ensure_clean_start(ctx: PipelineContext) -> None:
    status = run(["git", "status", "--porcelain"], ctx.repo_root, check=True).stdout
    (ctx.run_dir / "initial-status.txt").write_text(status, encoding="utf-8")
    if status and not ctx.config.get("allowDirtyStart", False):
        raise RuntimeError("worktree is dirty and allowDirtyStart is false")


def remote_is_allowed(ctx: PipelineContext, remote_name: str, allowed: str) -> bool:
    remote = run(["git", "remote", "get-url", "--push", remote_name], ctx.repo_root, check=True)
    remote_url = remote.stdout.strip()
    allowed_urls = {
        f"git@github.com:{allowed}.git",
        f"https://github.com/{allowed}.git",
        f"https://github.com/{allowed}",
        f"ssh://git@github.com/{allowed}.git",
    }
    (ctx.run_dir / f"{remote_name}-remote-url.txt").write_text(
        remote_url + "\n",
        encoding="utf-8",
    )
    return remote_url in allowed_urls


def scan_staged_files(ctx: PipelineContext) -> None:
    result = run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        ctx.repo_root,
        check=True,
    )
    matches: list[str] = []
    for file_name in result.stdout.splitlines():
        path = ctx.repo_root / file_name
        if not path.is_file():
            continue
        text = path.read_text(errors="ignore")
        if PRIVATE_KEY.search(text):
            matches.append(file_name)
            continue
        for match in SECRET_ASSIGNMENT.finditer(text):
            value = match.group("value").strip().strip("\"'")
            if value.startswith("re.compile(") or value.lower() in PLACEHOLDERS:
                continue
            matches.append(file_name)
            break
    (ctx.run_dir / "secret-scan-matches.txt").write_text(
        "\n".join(matches) + ("\n" if matches else ""),
        encoding="utf-8",
    )
    if matches:
        raise RuntimeError("secret scan failed for staged files")


def prepare_branch(ctx: PipelineContext) -> None:
    base_branch = ctx.config.get("baseBranch", "development")
    downstream_remote = ctx.config.get("downstreamRemoteName", "athernex")
    downstream_branch = ctx.config.get("downstreamBranch", "retrospective")
    run(["git", "fetch", "--all", "--prune"], ctx.repo_root)
    run(["git", "switch", base_branch], ctx.repo_root, check=True)
    run(["git", "pull", "--ff-only"], ctx.repo_root)
    run(["git", "switch", "-c", ctx.branch_name], ctx.repo_root, check=True)
    downstream_ref = f"refs/remotes/{downstream_remote}/{downstream_branch}"
    ref_check = run(["git", "show-ref", "--verify", "--quiet", downstream_ref], ctx.repo_root)
    if ref_check.returncode == 0:
        write_log(ctx, f"fast-forwarding branch from {downstream_remote}/{downstream_branch}")
        run(["git", "merge", "--ff-only", f"{downstream_remote}/{downstream_branch}"], ctx.repo_root, check=True)
    else:
        write_log(ctx, f"downstream branch {downstream_remote}/{downstream_branch} not found; first run will create it")


def task_codex(ctx: PipelineContext, task: dict[str, Any]) -> None:
    prompt = task["prompt"]
    prompt_path = ctx.run_dir / f"{task['id']}.prompt.md"
    prompt_path.write_text(prompt, encoding="utf-8")
    if ctx.dry_run:
        write_log(ctx, f"dry run: would run codex task {task['id']}")
        return
    max_runs = int(task.get("maxRuns", 1))
    for index in range(max_runs):
        result = run(
            [
                "codex",
                "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "--cd",
                str(ctx.repo_root),
                prompt,
            ],
            ctx.repo_root,
        )
        (ctx.run_dir / f"{task['id']}-{index + 1}.stdout.log").write_text(
            result.stdout,
            encoding="utf-8",
        )
        (ctx.run_dir / f"{task['id']}-{index + 1}.stderr.log").write_text(
            result.stderr,
            encoding="utf-8",
        )
        if result.returncode != 0:
            raise RuntimeError(f"codex task {task['id']} failed with {result.returncode}")


def task_verify_artifact(ctx: PipelineContext, task: dict[str, Any]) -> None:
    missing: list[str] = []
    for file_name in task.get("requiredFiles", []):
        path = ctx.repo_root / file_name
        if not path.is_file():
            missing.append(file_name)
    if missing:
        raise RuntimeError(f"missing required files: {', '.join(missing)}")

    combined = "\n".join(
        (ctx.repo_root / file_name).read_text(errors="ignore")
        for file_name in task.get("requiredFiles", [])
    )
    missing_patterns = [
        pattern for pattern in task.get("requiredPatterns", []) if pattern not in combined
    ]
    if missing_patterns:
        raise RuntimeError(f"missing required patterns: {', '.join(missing_patterns)}")
    write_log(ctx, f"verified artifact task {task['id']}")


def task_verify_pushed(ctx: PipelineContext, task: dict[str, Any]) -> None:
    remote_name = task.get("remoteName", ctx.config.get("primaryRemoteName", "origin"))
    branch_name = task.get("branchName", ctx.branch_name)
    if task.get("branchMustExistOnRemote", False):
        result = run(["git", "ls-remote", "--heads", remote_name, branch_name], ctx.repo_root)
        (ctx.run_dir / f"ls-remote-{remote_name}-{branch_name.replace('/', '-')}.txt").write_text(
            result.stdout,
            encoding="utf-8",
        )
        if ctx.dry_run:
            write_log(ctx, "dry run: skipped remote branch existence assertion")
        elif not result.stdout.strip():
            raise RuntimeError(f"remote branch was not found after push: {remote_name}/{branch_name}")

    if not ctx.dry_run:
        for file_name in task.get("requiredFiles", []):
            result = run(
                ["git", "show", f"{remote_name}/{branch_name}:{file_name}"],
                ctx.repo_root,
            )
            if result.returncode != 0:
                raise RuntimeError(f"file not present on pushed branch {remote_name}/{branch_name}: {file_name}")
    write_log(ctx, f"verified pushed repo task {task['id']}")


def run_verify_command(ctx: PipelineContext) -> None:
    command = ctx.config.get("verifyCommand")
    if not command:
        return
    result = run(["bash", "-lc", command], ctx.repo_root)
    (ctx.run_dir / "verify.stdout.log").write_text(result.stdout, encoding="utf-8")
    (ctx.run_dir / "verify.stderr.log").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"verify command failed: {command}")


def commit_and_push(ctx: PipelineContext) -> None:
    diff = run(["git", "status", "--porcelain"], ctx.repo_root, check=True).stdout
    (ctx.run_dir / "final-status.txt").write_text(diff, encoding="utf-8")
    if ctx.dry_run:
        write_log(ctx, "dry run: skipped commit and push")
        return
    if not diff.strip():
        write_log(ctx, "no changes to commit")
        return
    run(["git", "add", "--all"], ctx.repo_root, check=True)
    scan_staged_files(ctx)
    run(
        ["git", "commit", "-m", f"chore: neuroplexis planning dry run {utc_stamp()}"],
        ctx.repo_root,
        check=True,
    )
    if ctx.config.get("pushBranch", False):
        primary_remote = ctx.config.get("primaryRemoteName", "origin")
        primary_allowed = ctx.config.get("primaryAllowedRemoteRepo", "CharlesDerek/lab")
        downstream_remote = ctx.config.get("downstreamRemoteName", "athernex")
        downstream_allowed = ctx.config.get("downstreamAllowedRemoteRepo", "Athernex/orchestrator")
        downstream_branch = ctx.config.get("downstreamBranch", "retrospective")
        if not remote_is_allowed(ctx, primary_remote, primary_allowed):
            raise RuntimeError("primary remote is not allowlisted")
        if not remote_is_allowed(ctx, downstream_remote, downstream_allowed):
            raise RuntimeError("downstream remote is not allowlisted")
        run(
            ["git", "push", "-u", primary_remote, f"{ctx.branch_name}:{ctx.branch_name}"],
            ctx.repo_root,
            check=True,
        )
        run(
            ["git", "push", downstream_remote, f"HEAD:{downstream_branch}"],
            ctx.repo_root,
            check=True,
        )


def write_summary(ctx: PipelineContext, status: str, error: str | None = None) -> None:
    payload = {
        "status": status,
        "error": error,
        "branch": ctx.branch_name,
        "dryRun": ctx.dry_run,
        "runDir": str(ctx.run_dir),
        "configName": ctx.config.get("name"),
    }
    (ctx.run_dir / "summary.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def execute(config_path: Path, dry_run: bool) -> int:
    config = load_config(config_path)
    repo_root = Path(config["repoRoot"]).expanduser().resolve()
    stamp = utc_stamp()
    branch_name = f"{config.get('branchPrefix', 'routine/neuroplexis')}-{stamp}"
    run_dir = repo_root / ".paperclip" / "pipelines" / config.get("name", "pipeline") / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    ctx = PipelineContext(config=config, repo_root=repo_root, run_dir=run_dir, branch_name=branch_name, dry_run=dry_run)
    try:
        write_log(ctx, f"starting pipeline {config.get('name')} dry_run={dry_run}")
        ensure_clean_start(ctx)
        if not dry_run:
            prepare_branch(ctx)
        else:
            write_log(ctx, f"dry run: would create branch {branch_name}")
        post_push_tasks: list[dict[str, Any]] = []
        for task in config.get("tasks", []):
            task_type = task["type"]
            if task_type == "verify_pushed":
                post_push_tasks.append(task)
                write_log(ctx, f"task deferred until after push: {task['id']}")
                continue
            write_log(ctx, f"task start: {task['id']} ({task_type})")
            if task_type == "codex":
                task_codex(ctx, task)
            elif task_type == "verify_artifact":
                if dry_run:
                    write_log(ctx, f"dry run: skipped artifact assertion {task['id']}")
                else:
                    task_verify_artifact(ctx, task)
            else:
                raise RuntimeError(f"unknown task type: {task_type}")
            write_log(ctx, f"task done: {task['id']}")
        if not dry_run:
            run_verify_command(ctx)
        commit_and_push(ctx)
        for task in post_push_tasks:
            write_log(ctx, f"task start: {task['id']} ({task['type']})")
            task_verify_pushed(ctx, task)
            write_log(ctx, f"task done: {task['id']}")
        write_summary(ctx, "passed")
        return 0
    except Exception as exc:
        write_summary(ctx, "failed", str(exc))
        write_log(ctx, f"failed: {exc}")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="paperclip/pipelines/neuroplexis-planning-dry-run.json",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    return execute(Path(args.config), args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
