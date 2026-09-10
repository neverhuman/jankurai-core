#!/usr/bin/env bash
# PRs compare with protected main; resulting-main runs compare with its parent.
set -euo pipefail
base="$(git rev-parse --verify 'origin/main^{commit}')"
head="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ "$base" == "$head" ]]; then
  base="$(git rev-parse --verify 'HEAD^1^{commit}')"
fi
git merge-base --is-ancestor "$base" "$head" || {
  echo 'CI comparison base must be an ancestor of the current revision' >&2
  exit 1
}
printf '%s\n' "$base"
