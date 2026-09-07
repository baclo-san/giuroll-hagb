//! Whose inputs are known, what was guessed for the rest, and when that guess
//! turns out to have been wrong.
//!
//! This is the part of rollback that has nothing to do with the game. It is
//! pure bookkeeping over N input streams, so it lives on its own and is tested
//! without launching Soku -- the same reason the savestate work was proved with
//! a local sync test before any of it was put on a wire. A desync caused by
//! miscounting confirmations is indistinguishable, from the outside, from one
//! caused by a savestate gap, and it is debugged in the wrong place for weeks.
//!
//! WHY THIS EXISTS SEPARATELY FROM `Netcoder`. The existing netcoder is built
//! around exactly one opponent: `opponent_inputs`, `last_opponent_confirm`,
//! `last_opponent_delay`, `initial_opponent_max_rollback`. That is not a
//! limitation that generalises by renaming things -- with one opponent, "the
//! frame everyone agrees on" is just "the last frame they sent", and the
//! distinction between *known*, *guessed* and *confirmed* collapses. With three
//! opponents it does not, and the collapse is where the bugs live.

/// The most players a match can have. 4PSoku's 2v2 is the reason this is not 2.
pub const MAX_PLAYERS: usize = 4;

/// What we assume a player did on a frame we have not heard about yet.
///
/// Repeating their last input is the standard guess and by far the best cheap
/// one: inputs in a fighting game are held across frames far more often than
/// they change, so most guesses are right and cost nothing. A wrong guess is
/// not an error, it is the normal case rollback exists to absorb.
fn predict(last_known: Option<u16>) -> u16 {
    last_known.unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rollback {
    /// First frame that has to be simulated again.
    pub from: usize,
}

pub struct PeerInputs {
    players: usize,
    /// Inputs we have actually been told about. `None` means not yet heard.
    known: Vec<Vec<Option<u16>>>,
    /// What was fed to the engine when a frame was simulated, guessed or not.
    ///
    /// Kept separately from `known` because that is the only way to notice a
    /// guess was wrong: when the truth arrives for a frame already simulated,
    /// it is compared against what was *used*, not against what is now known.
    used: Vec<Vec<Option<u16>>>,
    /// Highest frame at which every player's input is known, plus one -- i.e.
    /// the first frame that is still uncertain.
    confirmed: usize,
    /// Earliest frame needing re-simulation, if a guess has been contradicted.
    pending_rollback: Option<usize>,
}

impl PeerInputs {
    pub fn new(players: usize) -> Self {
        assert!(
            (2..=MAX_PLAYERS).contains(&players),
            "players must be 2..={MAX_PLAYERS}, got {players}"
        );
        Self {
            players,
            known: vec![Vec::new(); players],
            used: vec![Vec::new(); players],
            confirmed: 0,
            pending_rollback: None,
        }
    }

    pub fn players(&self) -> usize {
        self.players
    }

    fn grow(v: &mut Vec<Option<u16>>, frame: usize) {
        if v.len() <= frame {
            v.resize(frame + 1, None);
        }
    }

    /// Record a player's real input for a frame.
    ///
    /// Returns a rollback when this contradicts a guess already simulated. Late
    /// duplicates are ignored rather than treated as conflicts: with UDP the
    /// same input arrives more than once routinely, and a resend that agrees
    /// with what we already had is not news.
    pub fn receive(&mut self, player: usize, frame: usize, input: u16) -> Option<Rollback> {
        assert!(player < self.players);
        Self::grow(&mut self.known[player], frame);

        match self.known[player][frame] {
            // Already knew it. Only worth complaining if the peer contradicts
            // itself, which means the stream is corrupt rather than merely late.
            Some(old) => {
                debug_assert_eq!(
                    old, input,
                    "peer {player} gave two different inputs for frame {frame}"
                );
                return None;
            }
            None => self.known[player][frame] = Some(input),
        }

        self.advance_confirmed();

        // Was this frame already simulated with a guess, and was the guess wrong?
        let guessed = self.used[player].get(frame).copied().flatten();
        if guessed.is_some_and(|g| g != input) {
            let from = self.pending_rollback.map_or(frame, |p| p.min(frame));
            self.pending_rollback = Some(from);
            return Some(Rollback { from });
        }
        None
    }

    /// Our own input, which is known the moment it is produced.
    pub fn set_local(&mut self, player: usize, frame: usize, input: u16) {
        self.receive(player, frame, input);
    }

    /// The input to simulate `frame` with, guessing where necessary, and a note
    /// that it was guessed so a later contradiction can be spotted.
    pub fn take_for_simulation(&mut self, frame: usize) -> Vec<u16> {
        let mut out = Vec::with_capacity(self.players);
        for p in 0..self.players {
            let input = match self.known[p].get(frame).copied().flatten() {
                Some(known) => known,
                None => {
                    let last = self.known[p][..frame.min(self.known[p].len())]
                        .iter()
                        .rev()
                        .find_map(|x| *x);
                    predict(last)
                }
            };
            Self::grow(&mut self.used[p], frame);
            self.used[p][frame] = Some(input);
            out.push(input);
        }
        out
    }

    /// What a frame was actually simulated with, if it has been simulated.
    pub fn used_at(&self, player: usize, frame: usize) -> Option<u16> {
        self.used[player].get(frame).copied().flatten()
    }

    /// First frame not yet known for every player.
    pub fn confirmed(&self) -> usize {
        self.confirmed
    }

    fn advance_confirmed(&mut self) {
        'outer: loop {
            for p in 0..self.players {
                match self.known[p].get(self.confirmed) {
                    Some(Some(_)) => (),
                    _ => break 'outer,
                }
            }
            self.confirmed += 1;
        }
    }

    /// Take the pending rollback, if any. Frames from `from` onwards must be
    /// simulated again with what is now known.
    pub fn take_rollback(&mut self) -> Option<Rollback> {
        self.pending_rollback.take().map(|from| Rollback { from })
    }

    /// May the game simulate `frame`, or must it wait?
    ///
    /// Guessing further ahead than the rollback budget is not merely
    /// inaccurate, it is unrecoverable: the savestate needed to correct it will
    /// have been dropped. Stalling for a frame is how that is avoided, and it
    /// is what the budget is for.
    pub fn can_simulate(&self, frame: usize, max_rollback: usize) -> bool {
        frame < self.confirmed + max_rollback + 1
    }

    /// Frames that can be dropped: everything strictly before `confirmed` is
    /// agreed by everyone and can never be rolled back to again.
    pub fn discardable_before(&self) -> usize {
        self.confirmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everyone's input arrives before the frame is simulated: nothing should
    /// ever roll back, and every frame should run on real inputs rather than
    /// guesses.
    ///
    /// Arriving first is what makes a connection "perfect" here. Simulating
    /// first and hearing afterwards is prediction, which is the next test.
    #[test]
    fn perfect_connection_never_rolls_back() {
        let mut pi = PeerInputs::new(4);
        for frame in 0..50 {
            for p in 0..4 {
                assert_eq!(pi.receive(p, frame, (frame * 10 + p) as u16), None);
            }
            let used = pi.take_for_simulation(frame);
            assert_eq!(used.len(), 4);
            for p in 0..4 {
                assert_eq!(used[p], (frame * 10 + p) as u16, "frame {frame}");
            }
        }
        assert_eq!(pi.confirmed(), 50);
        assert_eq!(pi.take_rollback(), None);
    }

    /// A guess that turns out to be right must not cause a rollback. This is
    /// the common case -- inputs are held far more often than they change --
    /// and rolling back on every late packet regardless of content would make
    /// the whole thing pointless.
    #[test]
    fn correct_guess_costs_nothing() {
        let mut pi = PeerInputs::new(2);
        pi.receive(0, 0, 0x55);
        pi.receive(1, 0, 0x55);
        pi.take_for_simulation(0);

        // Frame 1 simulated before player 1 is heard from; guess repeats 0x55.
        let used = pi.take_for_simulation(1);
        assert_eq!(used[1], 0x55);

        pi.receive(0, 1, 0x55);
        assert_eq!(pi.receive(1, 1, 0x55), None, "guess was right");
        assert_eq!(pi.take_rollback(), None);
    }

    #[test]
    fn wrong_guess_rolls_back_to_that_frame() {
        let mut pi = PeerInputs::new(2);
        pi.receive(0, 0, 0x55);
        pi.receive(1, 0, 0x55);
        pi.take_for_simulation(0);
        pi.take_for_simulation(1);
        pi.take_for_simulation(2);

        pi.receive(0, 1, 0x55);
        let rb = pi.receive(1, 1, 0x99).expect("guess was wrong");
        assert_eq!(rb, Rollback { from: 1 });
    }

    /// Two peers contradict guesses on different frames; the rollback must go
    /// to the EARLIER one. Rolling back to the later one leaves the earlier
    /// frame simulated from a known-wrong input, which is a silent desync.
    #[test]
    fn rollback_goes_to_earliest_contradiction() {
        let mut pi = PeerInputs::new(4);
        for p in 0..4 {
            pi.receive(p, 0, 0x01);
        }
        for f in 0..6 {
            pi.take_for_simulation(f);
        }

        pi.receive(3, 4, 0xAA);
        pi.receive(2, 2, 0xBB);
        assert_eq!(pi.take_rollback(), Some(Rollback { from: 2 }));
        assert_eq!(pi.take_rollback(), None, "taking clears it");
    }

    /// Confirmation is gated by the SLOWEST player, which is the whole
    /// difference between one opponent and three. With one opponent this test
    /// is vacuous; with three it is the thing most likely to be got wrong.
    #[test]
    fn confirmed_is_pinned_by_the_laggard() {
        let mut pi = PeerInputs::new(4);
        for frame in 0..10 {
            for p in 0..3 {
                pi.receive(p, frame, 1);
            }
        }
        assert_eq!(pi.confirmed(), 0, "player 3 has said nothing");

        for frame in 0..4 {
            pi.receive(3, frame, 1);
        }
        assert_eq!(pi.confirmed(), 4, "caught up only as far as player 3");

        for frame in 4..10 {
            pi.receive(3, frame, 1);
        }
        assert_eq!(pi.confirmed(), 10);
    }

    /// Out-of-order arrival is normal on UDP and must not advance confirmation
    /// past a hole.
    #[test]
    fn a_hole_blocks_confirmation() {
        let mut pi = PeerInputs::new(2);
        for f in [0usize, 1, 3, 4] {
            pi.receive(0, f, 1);
            pi.receive(1, f, 1);
        }
        assert_eq!(pi.confirmed(), 2, "frame 2 is missing");

        pi.receive(0, 2, 1);
        pi.receive(1, 2, 1);
        assert_eq!(pi.confirmed(), 5, "hole filled, jumps to the end");
    }

    #[test]
    fn duplicate_delivery_is_not_a_contradiction() {
        let mut pi = PeerInputs::new(2);
        pi.receive(0, 0, 7);
        pi.receive(1, 0, 7);
        pi.take_for_simulation(0);
        assert_eq!(pi.receive(1, 0, 7), None);
        assert_eq!(pi.take_rollback(), None);
    }

    /// The budget must stop the game running away from an unconfirmed frame,
    /// because the savestate needed to correct it would be gone.
    #[test]
    fn cannot_outrun_the_rollback_budget() {
        let pi = PeerInputs::new(2);
        assert!(pi.can_simulate(0, 6));
        assert!(pi.can_simulate(6, 6));
        assert!(!pi.can_simulate(7, 6), "7 frames ahead of nothing confirmed");
    }

    /// Guessing repeats the last KNOWN input, not the last used one -- so a
    /// hole does not make the guess drift.
    #[test]
    fn guess_repeats_last_known_across_a_hole() {
        let mut pi = PeerInputs::new(2);
        pi.receive(0, 0, 0x11);
        pi.receive(1, 0, 0x42);
        for f in 0..5 {
            let used = pi.take_for_simulation(f);
            assert_eq!(used[1], 0x42, "frame {f} should still guess 0x42");
        }
    }

    #[test]
    #[should_panic]
    fn rejects_impossible_player_counts() {
        PeerInputs::new(5);
    }
}
