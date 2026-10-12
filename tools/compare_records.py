#!/usr/bin/env python3
"""Compare giuroll 4P match records (.g4r) from the machines of one match.

    python compare_records.py FILE.g4r FILE.g4r [...]
    python compare_records.py DIRECTORY          # every match found in it

Each machine writes records/<seed>-slot<N>.g4r beside giuroll.ini; collect
them from all players into one folder. Files are grouped by match seed.
Playing the match's replay back writes <seed>-playback.g4r: the same match
simulated once, without rollback, to say which machines were right.

For each match it reports:
  * whether every machine was fed the same inputs on every common frame (if
    not, the fault is delivery, and nothing after that frame means anything);
  * the first frame on which the machines' game state differs, which values,
    each machine's value, and which machines agree with each other.
"""
import os
import struct
import sys
from collections import defaultdict

# Must match giuroll's rollback::REGION_NAMES. 26 entries in 4p-test-13..18,
# whose "objects" value was always 0 (it read the wrong list); 30 from test-19.
_BASE = (
    [f"player {p} {what}" for p in range(1, 5) for what in ("pos x", "pos y", "action/hp")]
    + [f"player {p} hand" for p in range(1, 5)]
    + [f"player {p} held" for p in range(1, 5)]
    + [f"player {p} objects" for p in range(1, 5)]
)
NAMES_BY_COUNT = {
    26: _BASE + ["inputs p1+p2", "inputs p3+p4"],
    30: _BASE + [f"player {p} hit state" for p in range(1, 5)] + ["inputs p1+p2", "inputs p3+p4"],
}
REGION_NAMES = NAMES_BY_COUNT[30]
HEADER = struct.Struct("<4sBBBBIQ16s")
PLAYBACK = 0xFF  # seat byte of a record made by playing a replay back
CHARACTERS = [
    "Reimu", "Marisa", "Sakuya", "Alice", "Patchouli", "Youmu", "Remilia", "Yuyuko",
    "Yukari", "Suika", "Reisen", "Aya", "Komachi", "Iku", "Tenshi", "Sanae",
    "Cirno", "Meiling", "Utsuho", "Suwako",
]


def char_name(c):
    if c == 0xFF:
        return "-"
    return CHARACTERS[c] if c < len(CHARACTERS) else f"character {c}"


def load(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < HEADER.size:
        raise ValueError("too short")
    magic, players, slot, regions, _, seed, unix, build = HEADER.unpack_from(data)
    if magic not in (b"G4R1", b"G4R2"):
        raise ValueError("not a giuroll match record")
    off = HEADER.size
    chars = None
    if magic == b"G4R2":
        chars = tuple(data[off:off + 4])
        off += 4
    rec = struct.Struct("<I4H%dI" % regions)
    frames = {}
    while off + rec.size <= len(data):
        v = rec.unpack_from(data, off)
        frames[v[0]] = (v[1:5], v[5:])
        off += rec.size
    return {
        "path": path, "players": players, "slot": slot, "regions": regions,
        "seed": seed, "unix": unix, "build": build.rstrip(b"\0").decode(errors="replace"),
        "frames": frames, "chars": chars,
    }


def fmt_region(i, v, names=REGION_NAMES):
    if i < 12 and i % 3 != 2:
        return struct.unpack("<f", struct.pack("<I", v))[0].__format__(".4f")
    if i < 12:
        return f"action {v >> 16} hp {v & 0xffff}"
    if i < 16:
        cards = [str((v >> (8 * k)) & 0xFF) for k in range(4) if (v >> (8 * k)) & 0xFF != 0xFF]
        return "[" + ",".join(cards) + "]"
    if i < 20:
        s4 = lambda x: ((x & 0xF) ^ 8) - 8
        parts = [f"lr {s4(v)}", f"ud {s4(v >> 4)}"]
        parts += [f"{n} {(v >> (8 + 4 * k)) & 0xF}" for k, n in enumerate(["A", "B", "C", "D", "ch", "sc"])]
        return " ".join(parts)
    if i < 24:
        if len(names) == 26:
            return str(v)
        return "unreadable" if v == 0xFFFFFFFF else f"{v >> 24} objects, hash {v & 0xFFFFFF:06x}"
    if i < len(names) - 2:
        return f"{v:08x}"
    return f"{v >> 16:04x}/{v & 0xffff:04x}"


def compare(recs):
    recs = sorted(recs, key=lambda r: r["slot"])
    names = ["PLAYBACK" if r["slot"] == PLAYBACK else f"slot {r['slot']}" for r in recs]
    has_playback = any(r["slot"] == PLAYBACK for r in recs)
    print(f"match seed {recs[0]['seed']:08x}: " + ", ".join(
        f"{n} ({r['build']}, {len(r['frames'])} frames)" for n, r in zip(names, recs)))
    builds = {r["build"] for r in recs}
    if len(builds) > 1:
        print(f"  DIFFERENT BUILDS: {sorted(builds)} -- fix that before reading anything else")
    mixed = len({r["regions"] for r in recs}) > 1
    if mixed:
        # Positions, actions, hands and held counters mean the same in every
        # format; compare those. Lets a test-19 playback of a test-17/18
        # match still say which machines were right.
        print("  different record formats; comparing the 20 values they share")
    chars = next((r["chars"] for r in recs if r["chars"]), None)
    if chars:
        print("  characters: " + ", ".join(f"P{n + 1} {char_name(c)}" for n, c in enumerate(chars)))
    names_all = NAMES_BY_COUNT.get(recs[0]["regions"], [f"region {i}" for i in range(recs[0]["regions"])])
    n_state = 20 if mixed else recs[0]["regions"] - 2
    if has_playback:
        print("  PLAYBACK is this match replayed locally with no rollback: the machines that match it were right")
    missing = sorted(set(range(4)) - {r["slot"] for r in recs})
    if missing:
        print(f"  no record from slot(s) {missing}: a lone dissenter cannot be told from a lone correct machine")

    common = sorted(set.intersection(*(set(r["frames"]) for r in recs)))
    if not common:
        print("  no frames in common")
        return
    print(f"  frames in common: {common[0]}..{common[-1]} ({len(common)})")

    online = [(n, r) for n, r in zip(names, recs) if r["slot"] != PLAYBACK]
    for f in common:
        ins = [r["frames"][f][0] for _, r in online]
        if len(set(ins)) > 1:
            print(f"  INPUTS DIFFER at frame {f}:")
            for (n, _), i in zip(online, ins):
                print(f"    {n}: " + " ".join(f"{x:03x}" for x in i))
            print("  -> delivery fault; state comparison after this frame is meaningless")
            break
    else:
        print("  inputs identical on every common frame")

    for f in common:
        # The playback record knows no inputs, so the two input values are
        # left out whenever it takes part.
        regs = [r["frames"][f][1][:n_state] if has_playback or mixed else r["frames"][f][1] for r in recs]
        if len(set(regs)) == 1:
            continue
        print(f"  FIRST STATE DIFFERENCE at frame {f}:")
        for i in range(len(regs[0])):
            vals = [g[i] for g in regs]
            if len(set(vals)) == 1:
                continue
            groups = defaultdict(list)
            for n, v in zip(names, vals):
                groups[v].append(n)
            print(f"    {names_all[i]}:")
            for v, who in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                print(f"      {fmt_region(i, v, names_all):<40} {', '.join(who)}")
        # Context: the same values a few frames earlier, to see what led in.
        before = [x for x in common if x < f][-3:]
        if before:
            print(f"  (frames {before[0]}..{before[-1]} before it all agreed)")
        return
    print("  state identical on every common frame -- no desync in these records")


def main(args):
    paths = []
    for a in args:
        if os.path.isdir(a):
            paths += [os.path.join(a, n) for n in os.listdir(a) if n.endswith(".g4r")]
        else:
            paths.append(a)
    if not paths:
        print(__doc__)
        return 1
    by_seed = defaultdict(list)
    for p in paths:
        try:
            r = load(p)
        except (OSError, ValueError, struct.error) as e:
            print(f"skipping {p}: {e}")
            continue
        by_seed[r["seed"]].append(r)
    for seed, recs in sorted(by_seed.items(), key=lambda kv: min(r["unix"] for r in kv[1])):
        compare(recs)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
