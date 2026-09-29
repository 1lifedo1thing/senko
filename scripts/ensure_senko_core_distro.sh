#!/usr/bin/env bash
set -euo pipefail

SRC="${1:?usage: ensure_senko_core_distro.sh source-path}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATCH="${ROOT}/scripts/patches/senko-core-trim-distro.patch"
CONF_PATCH="${ROOT}/scripts/patches/senko-core-trim-conf.patch"
DISTRO="${SRC}/main/distro/senko/senko.go"

same_distro_code() {
  [ -f "${DISTRO}" ] || return 1
  grep -q '"github.com/xtls/xray-core/main/distro/senko"' "${SRC}/main/main.go" || return 1
  # an older checkout may carry the same imports with the old module name in
  # comments; compare executable lines so a renamed comment needs no source edit
  cmp -s \
    <(awk '
      /^diff --git a\/main\/distro\/senko\/senko.go/ { inside=1; next }
      /^diff --git / { inside=0 }
      inside && /^\+[^+]/ {
        sub(/^\+/, "")
        if ($0 !~ /^[[:space:]]*(\/\/|$)/) print
      }' "${PATCH}") \
    <(awk '$0 !~ /^[[:space:]]*(\/\/|$)/ { print }' "${DISTRO}")
}

if ! same_distro_code; then
  if git -C "${SRC}" apply --check "${PATCH}"; then
    git -C "${SRC}" apply "${PATCH}"
    same_distro_code || { echo "senko-core distro differs from the maintained patch" >&2; exit 1; }
  else
    echo "senko-core distro is missing or differs from the maintained patch" >&2
    exit 1
  fi
fi

# the senko_trim build tag only means something once this patch is in place
if ! git -C "${SRC}" apply --reverse --check "${CONF_PATCH}" 2>/dev/null; then
  if git -C "${SRC}" apply --check "${CONF_PATCH}"; then
    git -C "${SRC}" apply "${CONF_PATCH}"
  else
    echo "senko-core infra/conf differs from the maintained trim patch" >&2
    exit 1
  fi
fi
