#!/usr/bin/env bash
set -euo pipefail

SOURCE_BRANCH="${1:-$(git branch --show-current)}"
PRIMARY_REMOTE="${PRIMARY_REMOTE:-origin}"
PRIMARY_ALLOWED_REPO="${PRIMARY_ALLOWED_REPO:-CharlesDerek/lab}"
DOWNSTREAM_REMOTE="${DOWNSTREAM_REMOTE:-athernex}"
DOWNSTREAM_ALLOWED_REPO="${DOWNSTREAM_ALLOWED_REPO:-Athernex/orchestrator}"
DOWNSTREAM_BRANCH="${DOWNSTREAM_BRANCH:-retrospective}"

remote_matches_repo() {
  local remote_name="$1"
  local allowed_repo="$2"
  local remote_url
  remote_url="$(git remote get-url --push "$remote_name" 2>/dev/null || git remote get-url "$remote_name" 2>/dev/null || true)"
  case "$remote_url" in
    git@github.com:"$allowed_repo".git) return 0 ;;
    https://github.com/"$allowed_repo".git) return 0 ;;
    https://github.com/"$allowed_repo") return 0 ;;
    ssh://git@github.com/"$allowed_repo".git) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ -z "$SOURCE_BRANCH" ]]; then
  echo "Could not determine source branch." >&2
  exit 2
fi

if ! remote_matches_repo "$PRIMARY_REMOTE" "$PRIMARY_ALLOWED_REPO"; then
  echo "Refusing push: $PRIMARY_REMOTE is not allowlisted as $PRIMARY_ALLOWED_REPO." >&2
  exit 3
fi

if ! remote_matches_repo "$DOWNSTREAM_REMOTE" "$DOWNSTREAM_ALLOWED_REPO"; then
  echo "Refusing push: $DOWNSTREAM_REMOTE is not allowlisted as $DOWNSTREAM_ALLOWED_REPO." >&2
  exit 4
fi

echo "Pushing $SOURCE_BRANCH to $PRIMARY_REMOTE/$SOURCE_BRANCH first..."
git push -u "$PRIMARY_REMOTE" "$SOURCE_BRANCH:$SOURCE_BRANCH"

echo "Pushing same HEAD to $DOWNSTREAM_REMOTE/$DOWNSTREAM_BRANCH..."
git push "$DOWNSTREAM_REMOTE" "HEAD:$DOWNSTREAM_BRANCH"

echo "Dual push complete:"
echo "- $PRIMARY_REMOTE/$SOURCE_BRANCH"
echo "- $DOWNSTREAM_REMOTE/$DOWNSTREAM_BRANCH"
