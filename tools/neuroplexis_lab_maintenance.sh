#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-/home/charles/Documents/Software/github/lab}"
BASE_BRANCH="${BASE_BRANCH:-development}"
COMPONENT_AREA="${COMPONENT_AREA:-public-safe orchestration, Kafka power scheduling, Paperclip integration, and repo hygiene}"
MAX_CODEX_RUNS="${MAX_CODEX_RUNS:-5}"
VERIFY_COMMAND="${VERIFY_COMMAND:-make check}"
REPORT_DIR="${REPORT_DIR:-.paperclip/neuroplexis}"
ALLOW_DIRTY_START="${ALLOW_DIRTY_START:-false}"
PUSH_BRANCH="${PUSH_BRANCH:-false}"
DRY_RUN="${DRY_RUN:-false}"
REQUIRE_CODEX_CHANGE="${REQUIRE_CODEX_CHANGE:-true}"
AUTO_COMMIT="${AUTO_COMMIT:-false}"
COMMIT_MESSAGE_PREFIX="${COMMIT_MESSAGE_PREFIX:-chore: neuroplexis maintenance}"
REMOTE_NAME="${REMOTE_NAME:-origin}"
ALLOWED_REMOTE_REPO="${ALLOWED_REMOTE_REPO:-CharlesDerek/lab}"
PRIMARY_REMOTE="${PRIMARY_REMOTE:-origin}"
PRIMARY_ALLOWED_REPO="${PRIMARY_ALLOWED_REPO:-CharlesDerek/lab}"
DOWNSTREAM_REMOTE="${DOWNSTREAM_REMOTE:-athernex}"
DOWNSTREAM_ALLOWED_REPO="${DOWNSTREAM_ALLOWED_REPO:-Athernex/orchestrator}"
DOWNSTREAM_BRANCH="${DOWNSTREAM_BRANCH:-retrospective}"
SECRET_SCAN_PATTERN='(api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|secret|password|passwd|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'\'']?[^"'\''[:space:]]{8,}|-----BEGIN (RSA |OPENSSH |EC |DSA |)?PRIVATE KEY-----'

cd "$REPO_ROOT"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
branch_component="$(printf '%s' "$COMPONENT_AREA" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//;s/-$//' | cut -c1-48)"
branch_name="routine/neuroplexis-${branch_component:-lab}-${timestamp}"
run_dir="$REPORT_DIR/$timestamp"
mkdir -p "$run_dir"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$run_dir/run.log"
}

capture() {
  local name="$1"
  shift
  log "running: $*"
  if "$@" >"$run_dir/$name.stdout.log" 2>"$run_dir/$name.stderr.log"; then
    log "ok: $*"
    return 0
  fi
  local status=$?
  log "failed($status): $*"
  return "$status"
}

workspace_fingerprint() {
  {
    printf '## status\n'
    git status --porcelain=v1 --untracked-files=all
    printf '\n## unstaged diff\n'
    git diff --binary
    printf '\n## staged diff\n'
    git diff --cached --binary
    printf '\n## untracked files\n'
    git ls-files --others --exclude-standard -z |
      while IFS= read -r -d '' file_name; do
        if [[ -f "$file_name" ]]; then
          sha256sum "$file_name"
        else
          printf 'untracked-nonfile  %s\n' "$file_name"
        fi
      done
  }
}

remote_is_allowed() {
  local remote_name="${1:-$REMOTE_NAME}"
  local allowed_repo="${2:-$ALLOWED_REMOTE_REPO}"
  local remote_url
  remote_url="$(git remote get-url --push "$remote_name" 2>/dev/null || git remote get-url "$remote_name" 2>/dev/null || true)"
  [[ -n "$remote_url" ]] || return 1

  case "$remote_url" in
    git@github.com:"$allowed_repo".git) return 0 ;;
    https://github.com/"$allowed_repo".git) return 0 ;;
    https://github.com/"$allowed_repo") return 0 ;;
    ssh://git@github.com/"$allowed_repo".git) return 0 ;;
    *) return 1 ;;
  esac
}

scan_changed_files_for_secrets() {
  local matches_file="$run_dir/secret-scan-matches.txt"
  if python3 - "$matches_file" <<'PY'
import pathlib
import re
import subprocess
import sys

matches_file = pathlib.Path(sys.argv[1])
files = subprocess.check_output(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
    text=True,
).splitlines()
assignment = re.compile(
    r"(?P<key>api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|secret|password|passwd|private[_-]?key)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\"'\s#]{8,})",
    re.I,
)
private_key = re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA |)?PRIVATE KEY-----", re.I)
placeholder_values = {
    "replace-me",
    "replace-me-locally",
    "changeme",
    "change-me",
    "dummy",
    "example",
    "placeholder",
}
matches = []
for file_name in files:
    path = pathlib.Path(file_name)
    if not path.is_file():
        continue
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        continue
    if private_key.search(text):
        matches.append(file_name)
        continue
    for match in assignment.finditer(text):
        value = match.group("value").strip().strip("\"'")
        if value.startswith("re.compile("):
            continue
        if value.lower() in placeholder_values:
            continue
        matches.append(file_name)
        break

matches_file.write_text("\n".join(matches) + ("\n" if matches else ""), encoding="utf-8")
sys.exit(1 if matches else 0)
PY
  then
    return 0
  else
    log "secret scan failed; possible secret-like assignment found in staged files"
    log "see $matches_file for file names; refusing commit/push"
    return 1
  fi
}

dirty_status="$(git status --porcelain)"
if [[ -n "$dirty_status" && "$ALLOW_DIRTY_START" != "true" ]]; then
  log "refusing to start with dirty worktree; set ALLOW_DIRTY_START=true only when intentional"
  git status --short | tee "$run_dir/initial-status.txt" >/dev/null
  exit 2
fi

log "starting Neuroplexis lab maintenance"
log "repo=$REPO_ROOT"
log "base_branch=$BASE_BRANCH"
log "branch=$branch_name"
log "component_area=$COMPONENT_AREA"
log "dry_run=$DRY_RUN"
log "require_codex_change=$REQUIRE_CODEX_CHANGE"
log "auto_commit=$AUTO_COMMIT"
log "push_branch=$PUSH_BRANCH"
log "allowed_remote_repo=$ALLOWED_REMOTE_REPO"
log "primary_remote=$PRIMARY_REMOTE"
log "primary_allowed_repo=$PRIMARY_ALLOWED_REPO"
log "downstream_remote=$DOWNSTREAM_REMOTE"
log "downstream_allowed_repo=$DOWNSTREAM_ALLOWED_REPO"
log "downstream_branch=$DOWNSTREAM_BRANCH"

if [[ "$DRY_RUN" == "true" ]]; then
  log "dry run: checking command availability and writing simulated routine report"
  command -v git >"$run_dir/git-command.txt"
  command -v codex >"$run_dir/codex-command.txt" || log "dry run warning: codex command not found"
  git branch --show-current >"$run_dir/current-branch.txt"
  git status --short >"$run_dir/initial-status.txt"
  if capture "dry-run-verify" bash -lc "$VERIFY_COMMAND"; then
    verify_result="passed"
  else
    verify_result="failed"
  fi
  cat >"$run_dir/summary.md" <<EOF
# Neuroplexis Routine Dry Run Summary

- Timestamp: $timestamp
- Planned branch: $branch_name
- Current branch: $(cat "$run_dir/current-branch.txt")
- Base branch: $BASE_BRANCH
- Component area: $COMPONENT_AREA
- Max Codex runs requested: $MAX_CODEX_RUNS
- Verification command: \`$VERIFY_COMMAND\`
- Verification result: $verify_result

## What Was Simulated

- Confirmed the runner can create report directories.
- Confirmed Git is available.
- Checked whether Codex is available.
- Captured current branch and worktree status.
- Ran the verification command.
- Did not switch branches.
- Did not invoke \`codex --yolo\`.
- Did not commit or push.

## Current Worktree Status

\`\`\`text
$(cat "$run_dir/initial-status.txt")
\`\`\`
EOF
  log "dry run summary written to $run_dir/summary.md"
  exit 0
fi

if ! [[ "$MAX_CODEX_RUNS" =~ ^[1-9][0-9]*$ ]]; then
  log "MAX_CODEX_RUNS must be a positive integer"
  exit 2
fi

if ! command -v codex >/dev/null 2>&1; then
  log "codex command not found; refusing real maintenance run"
  exit 2
fi

git fetch --all --prune >"$run_dir/git-fetch.stdout.log" 2>"$run_dir/git-fetch.stderr.log" || true
git switch "$BASE_BRANCH"
git pull --ff-only || true
git switch -c "$branch_name"
if git show-ref --verify --quiet "refs/remotes/$DOWNSTREAM_REMOTE/$DOWNSTREAM_BRANCH"; then
  log "fast-forwarding routine branch from $DOWNSTREAM_REMOTE/$DOWNSTREAM_BRANCH"
  git merge --ff-only "$DOWNSTREAM_REMOTE/$DOWNSTREAM_BRANCH"
else
  log "downstream branch $DOWNSTREAM_REMOTE/$DOWNSTREAM_BRANCH not found; first run will create it"
fi

cat >"$run_dir/next-context.md" <<EOF
# Neuroplexis Lab Maintenance Context

Repo: $REPO_ROOT
Base branch: $BASE_BRANCH
Working branch: $branch_name
Component area: $COMPONENT_AREA

Goal: make small public-safe improvements to this lab repo. Preserve the public/private boundary. Do not add secrets, real topology, credentials, private IP inventories, BMC/IPMI details, vendor runbooks, or destructive automation.

Loop contract:
1. Pick one narrow task in the component area.
2. Implement it.
3. Run verification.
4. Record what changed, what failed, and what the next run should know.
5. Keep notes short enough to be useful to the next cycle.
6. The next cycle must pick a different incremental task unless the prior one failed.
EOF

codex_failed=false
verify_failed=false
no_change_failed=false
for run_number in $(seq 1 "$MAX_CODEX_RUNS"); do
  log "codex cycle $run_number/$MAX_CODEX_RUNS"
  prompt_file="$run_dir/codex-$run_number.prompt.md"
  before_fingerprint="$run_dir/fingerprint-before-$run_number.txt"
  after_fingerprint="$run_dir/fingerprint-after-$run_number.txt"
  workspace_fingerprint >"$before_fingerprint"
  cat >"$prompt_file" <<EOF
You are Neuroplexis maintaining Project Athernex in $REPO_ROOT.

Read $run_dir/next-context.md first.

Work only on this component area:
$COMPONENT_AREA

Do one small public-safe improvement. After editing, run or prepare for:
$VERIFY_COMMAND

This is cycle $run_number of $MAX_CODEX_RUNS. Leave a concrete repository change in this cycle; do not only inspect files, write a summary, or say that work is already complete. Use the handoff notes to choose a different incremental change from prior cycles.

Constraints:
- Create maintainable, scoped changes.
- Do not add secrets, real topology, credentials, private network inventories, BMC/IPMI details, or destructive power procedures.
- Respect the existing dirty worktree and never revert unrelated user changes.
- Prefer tests/docs/contracts/local scaffolding over risky automation.
- End by updating $run_dir/next-context.md with a compact handoff: changed files, verification result, open risks, and next recommended task.
EOF

  if ! capture "codex-$run_number" codex exec --dangerously-bypass-approvals-and-sandbox --cd "$REPO_ROOT" "$(cat "$prompt_file")"; then
    log "stopping after codex failure in cycle $run_number"
    codex_failed=true
    break
  fi

  workspace_fingerprint >"$after_fingerprint"
  if cmp -s "$before_fingerprint" "$after_fingerprint"; then
    log "codex cycle $run_number produced no repository changes"
    if [[ "$REQUIRE_CODEX_CHANGE" == "true" ]]; then
      log "stopping because REQUIRE_CODEX_CHANGE=true"
      no_change_failed=true
      break
    fi
  else
    log "codex cycle $run_number produced repository changes"
  fi

  if ! capture "verify-$run_number" bash -lc "$VERIFY_COMMAND"; then
    log "verification failed in cycle $run_number; refusing public commit/push after report collection"
    verify_failed=true
    break
  fi

  git status --short >"$run_dir/status-after-$run_number.txt"
  git diff --stat >"$run_dir/diffstat-after-$run_number.txt"
  git diff --patch >"$run_dir/diff-after-$run_number.patch"
done

git status --short >"$run_dir/final-status.txt"
git diff --stat >"$run_dir/final-diffstat.txt"
git diff --patch >"$run_dir/final-diff.patch"

cat >"$run_dir/summary.md" <<EOF
# Neuroplexis Routine Summary

- Timestamp: $timestamp
- Branch: $branch_name
- Base branch: $BASE_BRANCH
- Component area: $COMPONENT_AREA
- Max Codex runs requested: $MAX_CODEX_RUNS
- Verification command: \`$VERIFY_COMMAND\`

## Final Status

\`\`\`text
$(cat "$run_dir/final-status.txt")
\`\`\`

## Final Diffstat

\`\`\`text
$(cat "$run_dir/final-diffstat.txt")
\`\`\`

## Handoff

$(cat "$run_dir/next-context.md")
EOF

log "summary written to $run_dir/summary.md"

if [[ "$codex_failed" == "true" || "$verify_failed" == "true" || "$no_change_failed" == "true" ]]; then
  log "routine produced local evidence but will not commit or push because codex_failed=$codex_failed verify_failed=$verify_failed no_change_failed=$no_change_failed"
  exit 5
fi

if [[ "$AUTO_COMMIT" == "true" ]]; then
  if [[ -z "$(git status --porcelain)" ]]; then
    log "no changes to commit"
  else
    git add --all
    scan_changed_files_for_secrets
    git commit -m "$COMMIT_MESSAGE_PREFIX: $timestamp"
    log "committed routine changes"
  fi
else
  log "auto commit disabled; set AUTO_COMMIT=true to commit routine changes"
fi

if [[ "$PUSH_BRANCH" == "true" ]]; then
  if ! remote_is_allowed "$PRIMARY_REMOTE" "$PRIMARY_ALLOWED_REPO"; then
    log "primary remote guard failed; $PRIMARY_REMOTE is not allowlisted as $PRIMARY_ALLOWED_REPO"
    exit 3
  fi
  if ! remote_is_allowed "$DOWNSTREAM_REMOTE" "$DOWNSTREAM_ALLOWED_REPO"; then
    log "downstream remote guard failed; $DOWNSTREAM_REMOTE is not allowlisted as $DOWNSTREAM_ALLOWED_REPO"
    exit 4
  fi
  git push -u "$PRIMARY_REMOTE" "$branch_name:$branch_name"
  log "pushed branch $branch_name to $PRIMARY_REMOTE"
  git push "$DOWNSTREAM_REMOTE" "HEAD:$DOWNSTREAM_BRANCH"
  log "pushed same HEAD to $DOWNSTREAM_REMOTE/$DOWNSTREAM_BRANCH"
else
  log "branch left local; set PUSH_BRANCH=true to push routine branches"
fi
