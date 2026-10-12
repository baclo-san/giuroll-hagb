//! A record of every confirmed frame of a 4P match, one file per machine.
//!
//! WHY. A desync report is one frame from one machine's point of view, and two
//! of every four went missing. It can say two machines disagree; it cannot say
//! whether they agreed on every input up to that point, which machine went
//! wrong first, or let the match be replayed afterwards. With the same record
//! from all four machines, `tools/compare_records.py` answers all three.
//!
//! Written at the one moment a frame is final: when the rollbacker retires it,
//! all peers' inputs for it confirmed. The values are the same region values
//! the desync report compares, so the two always agree.
//!
//! Files go to `records/` beside giuroll.ini, named `<seed>-slot<N>.g4r`: the
//! match seed is shared by all four machines, so matching files pair up by
//! name. Only the newest KEEP_FILES are kept.
//!
//! Layout, little-endian:
//!   header:  b"G4R2", u8 players, u8 local_slot, u8 regions, u8 reserved,
//!            u32 seed, u64 unix_time, [u8; 16] build (NUL padded),
//!            u8 character[4] (0xFF: no such player)
//! G4R1 (4p-test-17/18) is the same without the characters.
//!   frames:  u32 frame, u16 input[4], u32 region[regions]
//! Inputs use giuroll's bit order: bit k = INPUT_KEYS_NUMBERS index k.

use std::io::{BufWriter, Write};
use std::path::PathBuf;

use crate::println;
use crate::INPUT_KEYS_NUMBERS;

const KEEP_FILES: usize = 40;

static mut WRITER: Option<BufWriter<std::fs::File>> = None;
static mut WRITTEN: usize = 0;
/// Directory giuroll.ini lives in; set during init.
pub static mut DIR: Option<PathBuf> = None;

/// gameParams.randomSeed (0x899D08 + 0x48), the one value all four machines
/// are handed for a match and nothing else shares.
unsafe fn match_seed() -> u32 {
    *(0x899D50 as *const u32)
}

/// Each player's character id (CharacterManager+0x34C), 0xFF where absent.
unsafe fn characters() -> [u8; 4] {
    let mut out = [0xFFu8; 4];
    let bm = *(0x8985E4 as *const usize);
    if !(0x00400000..0x7fff0000).contains(&bm) {
        return out;
    }
    for (n, c) in out.iter_mut().enumerate() {
        let p = *((bm + 0xc + n * 4) as *const usize);
        if (0x00400000..0x7fff0000).contains(&p) {
            *c = *((p + 0x34c) as *const u8);
        }
    }
    out
}

/// Seat number written for a record made by replaying a match locally.
pub const PLAYBACK_SLOT: usize = 0xFF;

/// Start the record for a new match. Anything still open is finished first.
pub unsafe fn start(players: usize, local_slot: usize) {
    finish();
    if players <= 2 {
        return;
    }
    open(players, local_slot);
}

/// Start a record of a replay being played back -- the same match, simulated
/// once, with no network and no rollback. Compared with the four machines'
/// records it says which of them got the match right.
pub unsafe fn start_playback() {
    finish();
    if crate::replay::four_player_mod_loaded() {
        open(4, PLAYBACK_SLOT);
    }
}

/// One played-back frame. Inputs are not known here, so they are left zero
/// and the comparison skips them for this record.
pub unsafe fn playback_frame(number: usize) {
    if WRITER.is_none() || number == 0 {
        return;
    }
    let regions = crate::rollback::region_values();
    frame(number, &[], &regions);
}

unsafe fn open(players: usize, local_slot: usize) {
    let Some(dir) = DIR.as_ref() else {
        return;
    };
    let dir = dir.join("records");
    if std::fs::create_dir_all(&dir).is_err() {
        println!("giuroll: could not create {:?}; no match record", dir);
        return;
    }
    prune(&dir);

    let seed = match_seed();
    let path = dir.join(match local_slot {
        PLAYBACK_SLOT => format!("{:08x}-playback.g4r", seed),
        n => format!("{:08x}-slot{}.g4r", seed, n),
    });
    let Ok(file) = std::fs::File::create(&path) else {
        println!("giuroll: could not create {:?}; no match record", path);
        return;
    };
    let mut w = BufWriter::new(file);
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut build = [0u8; 16];
    for (b, c) in build.iter_mut().zip(crate::FOURP_BUILD.bytes()) {
        *b = c;
    }

    let mut header = Vec::with_capacity(40);
    header.extend_from_slice(b"G4R2");
    header.push(players as u8);
    header.push(local_slot as u8);
    header.push(crate::rollback::REGION_NAMES.len() as u8);
    header.push(0);
    header.extend_from_slice(&seed.to_le_bytes());
    header.extend_from_slice(&unix.to_le_bytes());
    header.extend_from_slice(&build);
    // Which characters: a desync is usually one character's move, and the
    // 2026-10-12 one had to be matched to a lineup through the replay file.
    header.extend_from_slice(&characters());
    if w.write_all(&header).is_err() {
        return;
    }
    println!("giuroll: recording this match to {:?}", path);
    WRITER = Some(w);
    WRITTEN = 0;
}

/// One confirmed frame.
pub unsafe fn frame(number: usize, inputs: &[[bool; INPUT_KEYS_NUMBERS]], regions: &[u32]) {
    let Some(w) = WRITER.as_mut() else {
        return;
    };
    let mut buf = Vec::with_capacity(12 + regions.len() * 4);

    buf.extend_from_slice(&(number as u32).to_le_bytes());
    for slot in 0..4 {
        let mask: u16 = inputs
            .get(slot)
            .map(|i| {
                i.iter()
                    .enumerate()
                    .filter(|(_, held)| **held)
                    .map(|(bit, _)| 1u16 << bit)
                    .sum()
            })
            .unwrap_or(0);
        buf.extend_from_slice(&mask.to_le_bytes());
    }
    for r in regions {
        buf.extend_from_slice(&r.to_le_bytes());
    }
    if w.write_all(&buf).is_err() {
        WRITER = None;
        return;
    }
    WRITTEN += 1;
    // About every two seconds. A match that ends in a crash or a closed
    // window loses at most that much, and the flush costs nothing measurable.
    if WRITTEN % 120 == 0 {
        let _ = w.flush();
    }
}

pub unsafe fn finish() {
    if let Some(mut w) = WRITER.take() {
        let _ = w.flush();
    }
}

/// Keep the newest KEEP_FILES records. A session of rematches makes one per
/// match per machine, and nobody is going to clean the folder by hand.
fn prune(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "g4r"))
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .collect();
    if files.len() < KEEP_FILES {
        return;
    }
    files.sort();
    for (_, p) in &files[..files.len() + 1 - KEEP_FILES] {
        let _ = std::fs::remove_file(p);
    }
}
