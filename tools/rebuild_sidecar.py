#!/usr/bin/env python3
"""Rebuild a 4PSoku replay's .rep.4p from a giuroll match record.

    python rebuild_sidecar.py RECORD.g4r REPLAY.rep.4p

4PSoku up to 2026-10-13 wrote version-2 .4p files: P3/P4 input
taken from a copy the engine edits (buttons go missing) and indexed by a
counter that drifts from the game's frame count. Those replays diverge
early. A giuroll record of the same match holds every player's confirmed
raw input by battle frame -- exactly what a version-3 .4p holds -- so the
.4p can be rebuilt from it. The P3/P4 setup (characters, decks) is kept
from the old file; the old file is kept as .v2.bak.

Use the record of the match the replay is of: the record's seed is the
first part of its name, and compare_records.py prints the characters.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_records  # noqa: E402

HEADER = struct.Struct("<4sII")
PLAYERS_SIZE = 2 * 44


def main(record_path, sidecar_path):
    rec = compare_records.load(record_path)
    with open(sidecar_path, "rb") as f:
        old = f.read()
    magic, version, frames = HEADER.unpack_from(old)
    if magic != b"4PR2":
        sys.exit(f"{sidecar_path} is not a 4PSoku replay sidecar")
    players = old[HEADER.size:HEADER.size + PLAYERS_SIZE]
    if rec["chars"]:
        p3, p4 = players[0], players[44]
        if (p3, p4) != rec["chars"][2:4]:
            sys.exit(f"the record's P3/P4 are characters {rec['chars'][2:4]}, the replay's {(p3, p4)}: not the same match")

    last = max(rec["frames"])
    entries = []
    for f in range(last + 1):
        ins = rec["frames"].get(f, ((0, 0, 0, 0), None))[0]
        # Record order is P1..P4 in giuroll bit order, which is 4PSoku's
        # Inputs bit order for the twelve bits both use; the sidecar wants
        # P3, P4, P1, P2.
        ins = [x & 0xFFF for x in ins]
        entries.append(struct.pack("<4H", ins[2], ins[3], ins[0], ins[1]))

    backup = sidecar_path + ".v2.bak"
    if not os.path.exists(backup):
        os.replace(sidecar_path, backup)
    with open(sidecar_path, "wb") as f:
        f.write(HEADER.pack(b"4PR2", 3, len(entries)))
        f.write(players)
        f.write(b"".join(entries))
    print(f"wrote {len(entries)} frames (version 3) to {sidecar_path}; the old file is {backup}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
