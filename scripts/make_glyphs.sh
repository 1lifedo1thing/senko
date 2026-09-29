#!/usr/bin/env bash
# render the ui glyph sources to the png sizes springboard-era uikit loads
#
# every source is a 24pt outline drawn in white. the app tints the alpha at
# runtime, so one file serves every theme. the pngs are committed, so a build
# needs this script only after a source changes
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/app/icons/glyphs/src"
OUT="${ROOT}/app/icons/glyphs"
RSVG="${SENKO_RSVG:-rsvg-convert}"

command -v "${RSVG}" >/dev/null 2>&1 || { echo "rsvg-convert is required" >&2; exit 1; }

shopt -s nullglob
sources=("${SRC}"/*.svg)
[ "${#sources[@]}" -gt 0 ] || { echo "no glyph sources in ${SRC}" >&2; exit 1; }

# a png without a source would ship a glyph nothing can regenerate
for png in "${OUT}"/glyph-*.png; do
  base="$(basename "${png}" .png)"
  base="${base%@2x}"
  base="${base%@3x}"
  [ -f "${SRC}/${base#glyph-}.svg" ] || rm -f "${png}"
done

for svg in "${sources[@]}"; do
  name="glyph-$(basename "${svg}" .svg)"
  # ios 5 loads name.png and name@2x.png, ios 8 adds @3x
  "${RSVG}" -w 24 -h 24 "${svg}" -o "${OUT}/${name}.png"
  "${RSVG}" -w 48 -h 48 "${svg}" -o "${OUT}/${name}@2x.png"
  "${RSVG}" -w 72 -h 72 "${svg}" -o "${OUT}/${name}@3x.png"
done

echo "rendered ${#sources[@]} glyphs into ${OUT}"
