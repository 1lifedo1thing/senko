#!/usr/bin/env python3

from pathlib import Path
import re
import struct

emoji = Path(__file__).resolve().parent.parent / "app" / "emoji"
files = list(emoji.glob("*.png"))
# unicode 17 emoji-test E0.6 entries use the ios 5 font
if len(files) != 3290:
    raise SystemExit("old-ios emoji fallback set is incomplete")

names = {file.stem for file in files}
for sample in ("1f1f3-1f1f1", "1f469-200d-1f4bb", "1f310"):
    if sample not in names:
        raise SystemExit(f"missing emoji sequence: {sample}")
for native in ("1f603", "2764", "31-20e3"):
    if native in names:
        raise SystemExit(f"iOS 5 native emoji bundled: {native}")

for file in files:
    if not re.fullmatch(r"[0-9a-f]+(?:-[0-9a-f]+)*", file.stem):
        raise SystemExit(f"invalid emoji asset name: {file.name}")
    with file.open("rb") as stream:
        header = stream.read(24)
        if header[:8] != b"\x89PNG\r\n\x1a\n" or \
           struct.unpack(">II", header[16:24]) != (72, 72):
            raise SystemExit(f"invalid emoji PNG: {file.name}")

if not (emoji / "LICENSE-GRAPHICS").is_file() or not (emoji / "ATTRIBUTION.txt").is_file():
    raise SystemExit("emoji attribution is missing")

print(f"all {len(files)} emoji assets passed")
