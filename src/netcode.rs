#[cfg(feature = "logtofile")]
use log::info;
use std::{
    collections::HashMap,
    sync::atomic::Ordering::Relaxed,
    time::{Duration, Instant},
};
use windows::Win32::Networking::WinSock::{SOCKADDR, SOCKET};

use crate::{
    input_to_accum, println, ptr_wrap, rollback::Rollbacker, INPUT_KEYS_NUMBERS, LIKELY_DESYNCED,
    SOKU_FRAMECOUNT, TARGET_OFFSET, WARNING_FRAME_MISSING_1_COUNTDOWN,
    WARNING_FRAME_MISSING_2_COUNTDOWN,
};

#[derive(Clone, Debug)]
pub struct NetworkPacket {
    id: usize,
    desyncdetect: u8,

    delay: u8,
    max_rollback: u8,

    inputs: Vec<u16>, //also u8 in size? starts out at id + delay
    //confirms: Vec<bool>,
    last_confirm: usize,
    sync: Option<i32>,

    initial_max_rollback: Option<u8>,

    /// Per-region checksums of frame `id - 20`, in REGION_NAMES order.
    ///
    /// Empty in a 1v1, where `desyncdetect` already answers the only
    /// question worth asking and the packet has to stay byte-identical to
    /// stock giuroll's. Byte 3 of the header carries the count, so a
    /// receiver that has never heard of this reads zero of them and parses
    /// exactly what it always did.
    region_hashes: Vec<u32>,

    /// Which seat the sender occupies, when it knows.
    ///
    /// Rides in a header byte the format already leaves zero rather than in a
    /// new field, so that our packets stay readable by stock giuroll and its
    /// stay readable by us. A 1v1 against someone running the released build
    /// has to keep working; it simply reports None here and the single
    /// opponent's slot is the other one.
    slot: Option<u8>,
}

impl NetworkPacket {
    fn encode(&self) -> Box<[u8]> {
        let mut buf = [0; 400];
        // Byte 0 is the packet type and byte 1 the host flag, both stamped by
        // send_packet. Bytes 2 and 3 are left zero by every giuroll to date,
        // which is what makes byte 2 usable without breaking either direction.
        // Stored as slot+1 so that zero keeps meaning "not stated".
        buf[2] = self.slot.map_or(0, |s| s + 1);
        buf[3] = self.region_hashes.len() as u8;
        buf[4..8].copy_from_slice(&self.id.to_le_bytes()); //0
        buf[8] = self.desyncdetect;
        buf[9] = self.delay;
        buf[10] = self.max_rollback;

        buf[11] = self.inputs.len() as u8; //inputs, confirms are the same length

        for a in 0..self.inputs.len() {
            buf[(12 + a * 2)..(14 + a * 2)].copy_from_slice(&self.inputs[a].to_le_bytes());
        }

        let next = 12 + self.inputs.len() * 2;

        buf[next..next + 4].copy_from_slice(&self.last_confirm.to_le_bytes());
        let next = next + 4;

        buf[next..next + 4].copy_from_slice(&self.sync.unwrap_or(i32::MAX).to_le_bytes());
        let mut last = next + 4;

        // Before initial_max_rollback, whose presence is inferred from the
        // packet length -- appending after it would make that inference
        // read a checksum byte as a rollback setting.
        for h in &self.region_hashes {
            buf[last..last + 4].copy_from_slice(&h.to_le_bytes());
            last += 4;
        }

        if let Some(initial_max_rollback) = self.initial_max_rollback {
            buf[last] = initial_max_rollback;
            last += 1;
        }

        buf[0..last].to_vec().into_boxed_slice()
    }

    pub fn decode(d: &[u8]) -> Self {
        let slot = match d[2] {
            0 => None,
            n => Some(n - 1),
        };
        let id = usize::from_le_bytes(d[4..8].try_into().unwrap());
        let desyncdetect = d[8];
        let delay = d[9];
        let max_rollback = d[10];
        let inputsize = d[11];
        let inputs = (0..inputsize as usize)
            .map(|x| u16::from_le_bytes(d[12 + x * 2..12 + (x + 1) * 2].try_into().unwrap()))
            .collect();
        let lastend = 12 + inputsize as usize * 2;
        let last_confirm = usize::from_le_bytes(d[lastend..lastend + 4].try_into().unwrap());

        let lastend = lastend + 4 as usize;
        let syncraw = i32::from_le_bytes(d[lastend..lastend + 4].try_into().unwrap());

        let sync = match syncraw {
            i32::MAX => None,
            x => Some(x),
        };

        let lastend = lastend + 4 as usize;

        let region_count = d[3] as usize;
        let region_hashes: Vec<u32> = (0..region_count)
            .filter(|i| d.len() >= lastend + (i + 1) * 4)
            .map(|i| {
                u32::from_le_bytes(
                    d[lastend + i * 4..lastend + (i + 1) * 4].try_into().unwrap(),
                )
            })
            .collect();
        let lastend = lastend + region_hashes.len() * 4;

        let initial_max_rollback = (d.len() > lastend).then(|| d[lastend]);

        Self {
            id,
            desyncdetect,
            delay,
            max_rollback,
            inputs,
            last_confirm,
            sync,
            initial_max_rollback,
            region_hashes,
            slot,
        }
    }
}

#[derive(Clone, Debug)]
pub enum FrameTimeData {
    Empty,
    LocalFirst(Instant),
    RemoteFirst(Instant),
    Done(i32),
}

pub struct Netcoder {
    /// Per slot, so three peers cannot be mistaken for one another.
    ///
    /// These were single values when there was a single opponent, and the
    /// dedupe below is why they cannot stay that way: `opponent_inputs[frame]`
    /// being occupied used to mean "we already have this frame", but with three
    /// senders it would mean "somebody's frame arrived", and the other two
    /// would be dropped without a trace. Our own slot's entries go unused.
    last_opponent_confirm: Vec<usize>,

    id: usize,

    //ideally we shouldn't be keeping a separate input stack from the Rollbacker but for now it's what I have
    opponent_inputs: Vec<Vec<Option<u16>>>,
    last_opponent_input: Vec<usize>,

    inputs: Vec<u16>,

    send_times: HashMap<usize, Instant>,
    recv_delays: HashMap<usize, Duration>,
    real_rollback_to_be_showed: usize,

    pub delay: usize,
    pub max_rollback: usize,
    pub display_stats: bool,
    /// Each peer's own delay setting, keyed by slot.
    ///
    /// `last_opponent_delay` used to be assigned straight from whichever
    /// packet arrived most recently, which with one opponent is the same
    /// thing and with three is whoever spoke last. It made the on-screen
    /// figure flicker between peers -- reported live as the delay readout
    /// swapping between P2, P3 and P4 -- and it fed the stall threshold,
    /// so the frame budget moved around with it too.
    peer_delay: [usize; crate::peers::MAX_PLAYERS],
    /// Whether each peer currently disagrees with us, and whether that has
    /// already been reported.
    ///
    /// Per peer, not global. One flag shared by three comparisons means an
    /// agreeing peer clears the flag a diverging one just set, so "first
    /// seen" becomes "first seen since somebody else last agreed" -- which
    /// is not the frame anyone wants.
    peer_desynced: [bool; crate::peers::MAX_PLAYERS],
    desync_reported: [bool; crate::peers::MAX_PLAYERS],
    pub last_opponent_delay: usize,
    pub initial_opponent_max_rollback: Option<usize>,
    pub initial_my_max_rollback: usize,

    past_frame_starts: Vec<FrameTimeData>,

    pub receiver: std::sync::mpsc::Receiver<(NetworkPacket, Instant)>,
    time_syncs: Vec<i32>,
    last_median_sync: i32,

    pub autodelay_enabled: Option<i8>,

    old_to_be_sent: Option<NetworkPacket>,
    old_input: [bool; INPUT_KEYS_NUMBERS],
}

/// The packets are only sent once per frame; a packet contains all previous unconfirmed inputs; a lost "main" packet is not recovered whenever it's not neccesseary
impl Netcoder {
    pub fn new(
        receiver: std::sync::mpsc::Receiver<(NetworkPacket, Instant)>,
        my_max_rollback: u8,
        players: usize,
    ) -> Self {
        Self {
            last_opponent_confirm: vec![0; players],
            inputs: Vec::new(),

            opponent_inputs: vec![Vec::new(); players],

            send_times: HashMap::new(),
            recv_delays: HashMap::new(),
            real_rollback_to_be_showed: 0,

            peer_delay: [0; crate::peers::MAX_PLAYERS],
            peer_desynced: [false; crate::peers::MAX_PLAYERS],
            desync_reported: [false; crate::peers::MAX_PLAYERS],
            last_opponent_delay: 0,
            last_opponent_input: vec![0; players],
            id: 0,
            delay: 0,
            max_rollback: 6,
            display_stats: false,
            initial_opponent_max_rollback: None,
            initial_my_max_rollback: my_max_rollback as usize,

            past_frame_starts: Vec::new(),
            receiver,

            time_syncs: vec![],
            last_median_sync: 0,
            autodelay_enabled: None,

            old_to_be_sent: None,
            old_input: [false; INPUT_KEYS_NUMBERS],
        }
    }

    /// The frame every peer has confirmed, which is the slowest of them.
    ///
    /// With one opponent this was just their number. The distinction only
    /// appears with three, and getting it wrong the obvious way -- taking the
    /// newest confirmation rather than the oldest -- would let the game run
    /// ahead of a peer it has stopped hearing from, and drop the savestate it
    /// would need to recover.
    fn slowest_confirm(&self, local_slot: usize) -> usize {
        self.slowest_confirm_slot(local_slot).1
    }

    /// The same, and WHICH peer it was.
    ///
    /// With one opponent the answer was never in doubt. With three, "a frame is
    /// missing" without a slot number is a report that a stall happened and
    /// nothing about whose link caused it -- which is most of what there is to
    /// know.
    fn slowest_confirm_slot(&self, local_slot: usize) -> (usize, usize) {
        self.last_opponent_confirm
            .iter()
            .enumerate()
            .filter(|(slot, _)| *slot != local_slot)
            .map(|(slot, v)| (slot, *v))
            .min_by_key(|(_, v)| *v)
            .unwrap_or((local_slot, 0))
    }

    /// The newest frame received from the peer we have heard least from.
    fn slowest_input(&self, local_slot: usize) -> usize {
        self.slowest_input_slot(local_slot).1
    }

    /// The same, and which peer. See slowest_confirm_slot.
    fn slowest_input_slot(&self, local_slot: usize) -> (usize, usize) {
        self.last_opponent_input
            .iter()
            .enumerate()
            .filter(|(slot, _)| *slot != local_slot)
            .map(|(slot, v)| (slot, *v))
            .min_by_key(|(_, v)| *v)
            .unwrap_or((local_slot, 0))
    }

    /// returns whether or not we are allowed to proceed based on the confirmations we received
    /// and sends the following frame to the opponent
    pub fn process_and_send(
        &mut self,
        rollbacker: &mut Rollbacker,
        current_input: [bool; INPUT_KEYS_NUMBERS],
    ) -> u32 {
        let function_start_time = Instant::now();

        while self.past_frame_starts.len() <= self.id {
            self.past_frame_starts.push(FrameTimeData::Empty);
        }

        let is_p1;
        unsafe {
            // todo: take out to it's own function
            let netmanager = *(0x8986a0 as *const usize);

            //host only
            let delay_display = (netmanager + 0x80) as *mut u8;
            *ptr_wrap!(delay_display) = self.delay as u8;

            //client only
            let delay_display = (netmanager + 0x81) as *mut u8;
            *ptr_wrap!(delay_display) = self.delay as u8;

            is_p1 = netmanager != 0 && *ptr_wrap!(netmanager as *const usize) == 0x858cac;
        }

        //because it looks like soku locks the netcode untill the start of a new frame, we sometimes reach this point before the netcode has finished processing it's packet, for that reason:
        std::thread::sleep(Duration::from_millis(1));

        while let Ok((packet, time)) = self.receiver.try_recv() {
            if packet.id > self.id + 20 {
                //these are probably packets comming from the last round, we better avoid them

                continue;
            }

            // time how long it took us to handlne that frame.
            // If we did not handle it in time we just send a -1000, meaning the opponent will slow down by a 1000 microseconds,
            // later on it should be worth to send information about frames ariving way too late,
            // that would make the opponent pause, or severely slow down for multiple frames

            //todo, handle time data packets not ariving at all, by taking the time of arrival of the subsequent packet

            // Which stream does this belong to? The sender says so in a 4P
            // session; with one opponent there is only the other seat.
            let slot = match packet.slot {
                Some(s) if (s as usize) < self.opponent_inputs.len() => s as usize,
                Some(_) => continue,
                None => 1 - rollbacker.local_slot(),
            };
            if slot == rollbacker.local_slot() {
                continue;
            }

            if packet.id >= self.opponent_inputs[slot].len() {
                if !is_p1 {
                    //self.delay = packet.delay as usize;
                    self.max_rollback = packet.max_rollback as usize;
                }

                self.peer_delay[slot] = packet.delay as usize;

                // The worst peer, not the last one heard from. The budget
                // has to cover everyone, and a readout that changes with
                // whoever just sent a packet tells the player nothing.
                let local = rollbacker.local_slot();
                self.last_opponent_delay = self
                    .peer_delay
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != local && *i < self.opponent_inputs.len())
                    .map(|(_, d)| *d)
                    .max()
                    .unwrap_or(0);

                if self.display_stats {
                    unsafe {
                        crate::NEXT_DRAW_ENEMY_DELAY = Some(self.last_opponent_delay as i32)
                    };
                } else {
                    unsafe { crate::NEXT_DRAW_ENEMY_DELAY = None };
                }

                // is the first arrival of the newest packet
                let last = self
                    .past_frame_starts
                    .get(packet.id)
                    .cloned()
                    .unwrap_or(FrameTimeData::Empty);

                match last {
                    //bug! this value is set to -1000 even if we are less than 1000 microseconds from completing out frame, which is possible only for targets with
                    // less than 1000 microsecond ping. nevertheless it should be fixed at some point
                    FrameTimeData::Empty => {
                        //let r = if self.id + 1 < packet.id {
                        //    -((time.elapsed().as_micros()) as i128 / 100)
                        //} else {
                        //    -((time.elapsed().as_micros()) as i128 / 1000)
                        //};

                        while self.past_frame_starts.len() <= packet.id {
                            self.past_frame_starts.push(FrameTimeData::Empty);
                        }

                        self.past_frame_starts[packet.id] = FrameTimeData::RemoteFirst(time);
                        //Some(r)
                    }
                    FrameTimeData::LocalFirst(x) => {
                        let r = time
                            .checked_duration_since(x)
                            .unwrap_or_else(|| {
                                {
                                    {
                                        x.checked_duration_since(time)
                                            .expect("either of these opperation should succeed")
                                    }
                                }
                            })
                            .as_micros() as i128;
                        //info!("time passed: {}", r);

                        self.past_frame_starts[packet.id] = FrameTimeData::Done(r as i32);

                        //Some(r)
                    }

                    FrameTimeData::RemoteFirst(_) => {
                        //info!("same frame received twice");
                        ()
                    }
                    FrameTimeData::Done(_) => (),
                };

                //if let Some(my_diff) = my_diff {
                //    while self.past_frame_starts.len() <= packet.id {
                //        self.past_frame_starts.push(FrameTimeData::Empty);
                //    }
                //    self.past_frame_starts[packet.id] = FrameTimeData::Done(my_diff as i32);
                //}

                // handle opponents timing data
                if let Some(remote) = packet.sync {
                    //info!("frame diff {}", remote);
                    if remote < 0 {
                        TARGET_OFFSET.fetch_add(-remote.max(-5000), Relaxed);
                    } else {
                        match self
                            .past_frame_starts
                            .get(packet.id.saturating_sub((packet.inputs.len()) as usize))
                        {
                            Some(FrameTimeData::Done(local)) => {
                                let diff = *local - remote;

                                while packet.id > self.time_syncs.len() {
                                    self.time_syncs.push(0);
                                }
                                self.time_syncs.push(diff);

                                //TARGET_OFFSET.fetch_add(diff, Relaxed);
                            }
                            Some(FrameTimeData::RemoteFirst(_)) => {
                                //println!("frame diff: remote first");
                                TARGET_OFFSET.fetch_add(-200, Relaxed);
                            }
                            Some(_) => (),
                            None => (), //info!("no time packet"),
                        }
                    }
                    //info!("packet sync data: {:?}", x)
                }

                // Desync detection.
                //
                // The region checksums decide it whenever both sides have
                // them. They used to be only a sub-report of the weather
                // byte, printed if that byte happened to differ -- and that
                // byte is EIGHT BITS, so it agrees with a diverged peer far
                // more often than not. A live session found the divergence
                // only at frame 2127, by which point eleven of the twelve
                // regions differed and the report could localise nothing:
                // the state had gone wrong long before the byte noticed.
                //
                // The weather byte is still the fallback, because a 1v1
                // carries no region checksums and has to keep working.
                let frame = packet.id.saturating_sub(20);
                let weather_remote = packet.desyncdetect;
                let ours = rollbacker.region_hashes.get(&frame);
                let comparable_regions = ours.is_some()
                    && packet.region_hashes.len() == crate::rollback::REGION_NAMES.len();

                let differ = if comparable_regions {
                    ours.unwrap()[..] != packet.region_hashes[..]
                } else if let Some(weather_local) = rollbacker.weathers.get(&frame) {
                    // Only when we hold a real value for that frame.
                    // Defaulting a missing one to zero made every match
                    // report a desync at frame 0 against every peer, which
                    // lit the on-screen warning before anyone had moved.
                    *weather_local != weather_remote
                } else {
                    false
                };

                self.peer_desynced[slot] = differ;
                unsafe {
                    LIKELY_DESYNCED = self.peer_desynced.iter().any(|x| *x);
                }

                if differ && !self.desync_reported[slot] {
                    self.desync_reported[slot] = true;
                    let weather_local =
                        rollbacker.weathers.get(&frame).cloned().unwrap_or(0);
                    println!(
                        "DESYNC first seen at frame {} against peer slot {}: \
                         local weather {}, theirs {}",
                        frame, slot, weather_local, weather_remote
                    );
                    unsafe { report_regions(rollbacker, frame, slot, &packet.region_hashes) };
                    #[cfg(feature = "logtofile")]
                    info!(
                        "DESYNC: local: {}, remote: {}",
                        weather_local, weather_remote
                    )
                }
            }

            if let Some(initial_opponent_max_rollback) = packet.initial_max_rollback {
                // Given values choosen by p1 and p2, the max_rollback actually used will be:
                // - 6, if one of them is greater then 6 (the old default value), and the other
                //      is less then 6,
                // - the one nearset to 6, otherwise.
                //
                // Assuming all preferences of max rollback are single peaked, it can be proved
                // that, if the game automatically sets a max rollback by a binary function (f)
                // with rollbacks chosen by p1 and p2 (denoted as n1 and n2) as arguments, the
                // one used here is the only one that satisfies all the following:
                // 1. unanimous consent: f(n, n) = n;
                // 2. symmetry: f(n1, n2) = f(n2, n1);
                // 3. Pareto improvement to the default 6: f(n1, n2) is always not worse than 6
                //    for any player who likes n1 rollbacks most;
                // 4. Nash equilibrium: with rollback set by the opponent fixed, choosing the
                //    favorite rollback will always lead to the best result for a player;
                // 5. Pareto optimality: it is impossible that they dishonestly choose different
                //    rollbacks and finally get a result which is better for both of them;
                // 6. min(n1, n2) <= f(n1, n2) <= max(n1, n2).
                let initial_opponent_max_rollback = initial_opponent_max_rollback as usize;
                self.initial_opponent_max_rollback = Some(initial_opponent_max_rollback);
                let min = initial_opponent_max_rollback.min(self.initial_my_max_rollback);
                let max = initial_opponent_max_rollback.max(self.initial_my_max_rollback);
                self.max_rollback = if min < 6 && 6 < max {
                    6
                } else if max <= 6 {
                    max
                } else if min >= 6 {
                    min
                } else {
                    panic!("should be unreachable! max {}, min {}", max, min)
                };
            }

            let latest = packet.id as usize; //last delay
            while self.opponent_inputs[slot].len() <= latest as usize {
                self.opponent_inputs[slot].push(None);
            }
            let mut fr = latest;

            self.last_opponent_input[slot] = self.last_opponent_input[slot].max(packet.id);

            for a in (self.last_opponent_confirm[slot] + 1)..=packet.last_confirm {
                // Only the first peer to confirm a frame times it; the rest
                // would be measuring their own lateness against a send that was
                // already acknowledged.
                if let Some(sent) = self.send_times.get(&a) {
                    self.recv_delays
                        .entry(a)
                        .or_insert_with(|| time.saturating_duration_since(*sent));
                }
            }

            self.last_opponent_confirm[slot] = self.last_opponent_confirm[slot].max(packet.last_confirm);

            for a in packet.inputs {
                if self.opponent_inputs[slot][fr].is_none() {
                    //println!("{:?}", self.send_times[fr].elapsed());

                    // rollbacking to frame 0 causes problems (such as crash)
                    let inp_a = match fr {
                        0 => 0,
                        _ => a,
                    };

                    self.opponent_inputs[slot][fr] = Some(inp_a);

                    // todo: move into it's own function

                    let inp: [bool; INPUT_KEYS_NUMBERS] = (0..INPUT_KEYS_NUMBERS)
                        .into_iter()
                        .map(|x| (inp_a & (1 << x)) > 0)
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    rollbacker.insert_input(slot, inp, fr);
                }

                if fr == 0 {
                    break;
                }
                fr -= 1;
            }
        }

        // merge current input with the inputs from the time when the game was paused
        for (index, x) in current_input.into_iter().enumerate() {
            self.old_input[index] |= x;
        }
        let refresh_ping = || unsafe {
            if self.display_stats && self.id > 90 {
                let now = Instant::now();
                let max = ((self.id - 90)..self.id)
                    .map(|a| match self.recv_delays.get(&a) {
                        Some(x) => x.as_millis(),
                        None => now
                            .saturating_duration_since(self.send_times[&a])
                            .as_millis(),
                    })
                    .max()
                    .unwrap();
                let max = (max / 2) as i32;

                crate::NEXT_DRAW_PING = Some(max);
            }
        };

        unsafe {
            if self.display_stats {
                if self.id % 60 == 0 {
                    refresh_ping();
                }
            } else {
                crate::NEXT_DRAW_PING = None;
            }
        }

        let slowest_confirm = self.slowest_confirm(rollbacker.local_slot());
        let slowest_input = self.slowest_input(rollbacker.local_slot());

        let pause = if self.id > slowest_confirm + 30 {
            //crate::TARGET_OFFSET.fetch_add(1000 * m as i32, Relaxed);
            println!(
                "frame is missing: id: {}, confirm: {} (waiting on peer slot {})",
                self.id,
                slowest_confirm,
                self.slowest_confirm_slot(rollbacker.local_slot()).0
            );
            unsafe {
                WARNING_FRAME_MISSING_1_COUNTDOWN = 120;
                if self.display_stats {
                    refresh_ping();
                }
            }
            true
        } else if self.id
            > slowest_input
                + (self.max_rollback + self.delay.max(self.last_opponent_delay)).min(15)
        {
            //crate::TARGET_OFFSET.fetch_add(1000 * m as i32, Relaxed);
            println!(
                "frame is missing for reason 2: id: {}, input: {} (waiting on peer slot {})",
                self.id,
                slowest_input,
                self.slowest_input_slot(rollbacker.local_slot()).0
            );
            unsafe {
                WARNING_FRAME_MISSING_2_COUNTDOWN = 120;
                if self.display_stats {
                    refresh_ping();
                    self.real_rollback_to_be_showed = self
                        .real_rollback_to_be_showed
                        .max(self.id - slowest_input - 1 - self.delay);
                    crate::NEXT_DRAW_ROLLBACK = Some(self.real_rollback_to_be_showed as i32);
                }
            }
            true
        } else {
            false
        };
        if pause {
            if let Some(old_to_be_sent) = self.old_to_be_sent.as_mut() {
                old_to_be_sent.last_confirm =
                    slowest_input.min(old_to_be_sent.id + 30);
                old_to_be_sent.max_rollback = self.max_rollback as u8;
                unsafe {
                    send_packet(old_to_be_sent.encode());
                };
            }
            return 0;
        }

        let input_head = self.id;

        let input_range = slowest_confirm..=input_head;
        let merged_current_input = self.old_input;
        self.old_input = [false; INPUT_KEYS_NUMBERS];

        // do not override existing inputs; this can happen when delay is changed
        while rollbacker.self_inputs.len() <= input_head {
            // rollbacking to frame 0 causes problems (such as crash)
            let index = rollbacker.self_inputs.len();
            rollbacker.self_inputs.push(match index {
                0 => [false; INPUT_KEYS_NUMBERS],
                _ => merged_current_input,
            });
        }

        while self.inputs.len() <= input_head {
            // rollbacking to frame 0 causes problems (such as crash)
            let index = self.inputs.len();
            self.inputs.push(input_to_accum(&match index {
                0 => [false; INPUT_KEYS_NUMBERS],
                _ => merged_current_input,
            }));
        }

        let mut ivec = self.inputs[input_range.clone()].to_vec();
        ivec.reverse();

        let past = match self.past_frame_starts.get(self.id.saturating_sub(30)) {
            Some(FrameTimeData::Done(x)) => Some(*x),
            _ => None,
        };

        let to_be_sent = NetworkPacket {
            id: self.id,
            desyncdetect: rollbacker
                .weathers
                .get(&(self.id.saturating_sub(20)))
                .cloned()
                .unwrap_or(0),
            delay: self.delay as u8,
            max_rollback: self.max_rollback as u8,
            inputs: ivec,
            last_confirm: slowest_input.min(self.id + 30),
            sync: past,
            initial_max_rollback: (self.id <= 120).then_some(self.initial_my_max_rollback as u8),
            // Same frame `desyncdetect` describes, so both are checked
            // against one another rather than against two different frames.
            region_hashes: if rollbacker.players() > 2 {
                rollbacker
                    .region_hashes
                    .get(&self.id.saturating_sub(20))
                    .map(|h| h.to_vec())
                    .unwrap_or_default()
            } else {
                Vec::new()
            },
            // Say which seat this is, so three peers can be told apart. Left
            // unstated in a 1v1, where it carries no information and its
            // absence keeps the packet identical to stock giuroll's.
            slot: (rollbacker.players() > 2).then(|| rollbacker.local_slot() as u8),
        };
        self.old_to_be_sent = Some(to_be_sent.clone());

        unsafe { send_packet(to_be_sent.encode()) };
        self.send_times.insert(input_head, Instant::now());

        let m = rollbacker.start();

        let diff = self.id as i64 - unsafe { *SOKU_FRAMECOUNT } as i64;

        let m = if diff < (self.delay as i64) {
            m.saturating_sub(1)
        } else if diff > (self.delay as i64) {
            m + 1
        } else {
            m
        };

        //println!("m: {m}");

        //if rollbacker.guessed.len() > 13 {
        //    panic!("WHAT 13");
        //}

        unsafe {
            if self.display_stats {
                self.real_rollback_to_be_showed = rollbacker
                    .guessed
                    .len()
                    .max(self.real_rollback_to_be_showed);
                if self.id % 60 == 0 {
                    crate::NEXT_DRAW_ROLLBACK = Some(self.real_rollback_to_be_showed as i32);
                    self.real_rollback_to_be_showed = 0;
                }
            } else {
                crate::NEXT_DRAW_ROLLBACK = None;
                self.real_rollback_to_be_showed = 0;
            }

            if let Some(bias) = self.autodelay_enabled {
                if self.id == 100 {
                    //let id = self.id - 60;
                    let iter = (30..70)
                        .map(|x| self.recv_delays.get(&x))
                        .filter_map(|x| x)
                        .map(|x| x.as_micros());

                    let (count, sum) = iter.fold((0, 0), |x, y| (x.0 + 1, x.1 + y));
                    let avg = sum / count;
                    self.delay = ((avg.div_ceil(1_000_000 / 30)) as i8 - bias).clamp(0, 9) as usize;
                    println!("avg: {}, auto delay: {}", avg, self.delay);
                }
            }
        }

        //time sync
        const TIME_SYNC_MEDIAN_INTERVAL: usize = 50;
        if self.id % TIME_SYNC_MEDIAN_INTERVAL == 0 && self.id > (TIME_SYNC_MEDIAN_INTERVAL + 30) {
            match self
                .time_syncs
                .get((self.id - 30 - TIME_SYNC_MEDIAN_INTERVAL)..(self.id - 30))
                .map(|x| {
                    let ret: Result<[i32; TIME_SYNC_MEDIAN_INTERVAL], _> = x.try_into();
                    ret.ok()
                })
                .flatten()
            {
                Some(mut av) => {
                    av.sort();

                    //let median = (av[TIME_SYNC_MEDIAN_INTERVAL / 2 - 1]
                    //    + av[TIME_SYNC_MEDIAN_INTERVAL / 2])
                    //    / 2;
                    //println!("median: {median}");
                    let sum: i32 = av[3..TIME_SYNC_MEDIAN_INTERVAL - 3].iter().sum();
                    let average = sum / (TIME_SYNC_MEDIAN_INTERVAL as i32 - 6);
                    // println!("average: {average}");

                    self.last_median_sync = average;
                }
                None => (),
            }
        }
        if self.last_median_sync.abs() > 20000 {
            TARGET_OFFSET.fetch_add(self.last_median_sync / 700, Relaxed);
        } else if self.last_median_sync.abs() > 10000 {
            TARGET_OFFSET.fetch_add(self.last_median_sync / 1400, Relaxed);
        } else if self.last_median_sync.abs() > 2000 {
            TARGET_OFFSET.fetch_add(self.last_median_sync / 2000, Relaxed);
        } else {
            let res = if self.last_median_sync.abs() > 500 {
                self.last_median_sync.clamp(-1, 1)
            } else {
                0
            };
            TARGET_OFFSET.fetch_add(res, Relaxed);
        }

        {
            //todo: consider moving to it's own function
            match self.past_frame_starts[self.id].clone() {
                FrameTimeData::Empty => {
                    self.past_frame_starts[self.id] = FrameTimeData::LocalFirst(function_start_time)
                }
                FrameTimeData::LocalFirst(_) => todo!("should be unreachable"),
                FrameTimeData::RemoteFirst(x) => {
                    self.past_frame_starts[self.id] = FrameTimeData::Done(
                        x.saturating_duration_since(function_start_time).as_micros() as i32,
                    )
                }
                FrameTimeData::Done(_) => (),
            }

            self.id += 1;
            m as u32
        }
    }
}

/// Name the parts of the state that disagree, on the frame they first did.
///
/// The weather byte says a match diverged; this says where. Both peers dump the
/// state in the same order, so the checksums line up index for index and only
/// the numbers have to travel.
///
/// Reports the regions that MATCH as well, because that is often the more
/// useful half: "player 3 differs, everything else agrees" points somewhere,
/// and so does "everything differs", which means the divergence is older than
/// this frame and the report has arrived too late to localise anything.
unsafe fn report_regions(
    rollbacker: &Rollbacker,
    frame: usize,
    slot: usize,
    theirs: &[u32],
) {
    use crate::rollback::REGION_NAMES;

    let Some(ours) = rollbacker.region_hashes.get(&frame) else {
        println!(
            "  no region checksums kept for frame {} -- cannot say which part diverged",
            frame
        );
        return;
    };
    if theirs.is_empty() {
        // Not a version problem, whatever it looks like. A peer sends none
        // until it has retired a frame, and none at all in a 1v1. Saying
        // "different build" here sent everyone hunting a version mismatch
        // that did not exist.
        println!(
            "  peer slot {} had no checksums for frame {} yet -- too early in \
             the match to localise",
            slot, frame
        );
        return;
    }
    if theirs.len() != REGION_NAMES.len() {
        println!(
            "  peer slot {} sent {} region checksums, this build has {} -- \
             it is running a different giuroll, which is the thing to fix first",
            slot,
            theirs.len(),
            REGION_NAMES.len()
        );
        return;
    }

    let differing: Vec<&str> = REGION_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| ours[*i] != theirs[*i])
        .map(|(_, n)| *n)
        .collect();

    if differing.is_empty() {
        println!(
            "  every region agrees on frame {}, so only the weather byte differs",
            frame
        );
        return;
    }
    println!(
        "  regions differing on frame {}: {}",
        frame,
        differing.join(", ")
    );
    // Printed as the values they are. A hash would say two numbers differ;
    // these say a character is in the wrong place, or in the wrong move, or
    // took damage on one machine and not the other -- which is usually
    // enough to know what to look at without reading any more of the log.
    for (i, name) in REGION_NAMES.iter().enumerate() {
        if ours[i] == theirs[i] {
            continue;
        }
        if i % 3 == 2 {
            println!(
                "    {:<20} local action {} hp {}  slot {} action {} hp {}",
                name,
                ours[i] >> 16,
                ours[i] & 0xffff,
                slot,
                theirs[i] >> 16,
                theirs[i] & 0xffff
            );
        } else {
            println!(
                "    {:<20} local {}  slot {} {}",
                name,
                f32::from_bits(ours[i]),
                slot,
                f32::from_bits(theirs[i])
            );
        }
    }
}

pub unsafe fn send_packet(mut data: Box<[u8]>) {
    //info!("sending packet");
    data[0] = 0x6b;

    let netmanager = *(0x8986a0 as *const usize);

    let socket = netmanager + 0x3e4;

    let to;
    if *ptr_wrap!(netmanager as *const usize) == 0x858cac {
        let it = (netmanager + 0x4c8) as *const usize;
        data[1] = 1;

        if *it == 0 {
            panic!();
        }
        to = *(it as *const *const SOCKADDR);
    } else {
        data[1] = 2;

        if *(netmanager as *const usize) != 0x858d14 {
            panic!();
        }
        to = (netmanager + 0x47c) as *const SOCKADDR
    }

    // Straight to the peers that answered a hole punch. When every peer is
    // reachable that way the relay carries no battle traffic at all, which is
    // the entire point: at 150ms one-way an extra hop costs nearly two frames
    // of a fifteen-frame budget.
    if crate::mesh::send_to_peers(&data) {
        return;
    }

    // Otherwise the relay still carries a copy, for whichever pair could not be
    // punched. Peers already reached directly get that input twice and discard
    // the repeat, which PeerInputs does for any input it has seen before.

    // Some mods such as InfiniteDecks hook the import table of Soku
    let soku_sendto: unsafe extern "stdcall" fn(
        SOCKET,
        *const u8,
        i32,
        i32,
        *const SOCKADDR,
        i32,
    ) -> i32 = std::mem::transmute(0x0081f6c4);

    let rse = soku_sendto(
        *ptr_wrap!(socket as *const SOCKET),
        data.as_ptr(),
        data.len() as _,
        0,
        to,
        0x10,
    );

    if rse == -1 {
        //to do, change error handling for sockets

        //#[cfg(feature = "logtofile")]
        //info!("socket err: {:?}", WSAGetLastError());
    }
}

pub unsafe fn send_packet_untagged(data: Box<[u8]>) {
    //info!("sending packet");

    let netmanager = *(0x8986a0 as *const usize);

    let socket = netmanager + 0x3e4;

    let to;
    if *(netmanager as *const usize) == 0x858cac {
        let it = (netmanager + 0x4c8) as *const usize;
        //data[1] = 1;

        if *it == 0 {
            panic!();
        }
        to = *(it as *const *const SOCKADDR);
    } else {
        //data[1] = 2;

        if *(netmanager as *const usize) != 0x858d14 {
            panic!();
        }
        to = (netmanager + 0x47c) as *const SOCKADDR
    }

    // Some mods such as InfiniteDecks hook the import table of Soku
    let soku_sendto: unsafe extern "stdcall" fn(
        SOCKET,
        *const u8,
        i32,
        i32,
        *const SOCKADDR,
        i32,
    ) -> i32 = std::mem::transmute(0x0081f6c4);

    let rse = soku_sendto(
        *ptr_wrap!(socket as *const SOCKET),
        data.as_ptr(),
        data.len() as _,
        0,
        to,
        0x10,
    );

    if rse == -1 {
        //to do, change error handling for sockets

        //#[cfg(feature = "logtofile")]
        println!(
            "socket err: {:?}",
            windows::Win32::Networking::WinSock::WSAGetLastError()
        );
    }
}
