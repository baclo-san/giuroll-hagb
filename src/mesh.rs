//! Direct peer-to-peer paths between the four players, with the relay as
//! fallback.
//!
//! WHY. Under the relay every packet is bent through one machine, and with four
//! players that is six pairs all sharing one detour. It matters here because
//! the rollback budget is not generous: the game stalls once it gets more than
//! `(max_rollback + delay).min(15)` frames ahead of the SLOWEST peer, and at
//! 60fps 150ms of one-way latency is already nine of those fifteen frames. A
//! relay hop of even 30ms costs nearly two more. Across NA/EU/RU there is no
//! placement of a single relay that does not push at least one pair over.
//!
//! WHAT THIS IS NOT. It is not a replacement for the relay. The relay still
//! runs the lobby, assigns slots, carries character select, and tells everyone
//! where everyone else is -- it is the rendezvous that makes hole punching
//! possible at all. What moves off it is the per-frame battle input, which is
//! the only traffic latency-critical enough to care.
//!
//! FALLBACK IS PER PAIR, not all-or-nothing. Punching fails for real reasons --
//! symmetric NAT, CGNAT -- and one unreachable pair should not force the other
//! five back onto the relay. A peer we have not punched is simply addressed
//! through the relay while the rest go direct.
//!
//! Duplicate delivery is expected and harmless: while any peer is still on the
//! relay we send there as well, so punched peers receive some inputs twice.
//! `PeerInputs::receive` already ignores an input it has been told before, so
//! this costs bandwidth and nothing else.

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::{Duration, Instant};
use windows::Win32::Networking::WinSock::{SOCKADDR, SOCKET};

use crate::{peers::MAX_PLAYERS, println, ptr_wrap};

/// Relay -> client: where the other players are.
/// `[type][count]` then `count` × `[slot(1)][ip(4, network order)][port(2, network order)]`.
pub const PACKET_PEER_LIST: u8 = 0x78;

/// Client -> client: a hole-punch probe. `[type][sender slot][kind]`.
///
/// The third byte is PROBE or REPLY, and it is not decoration: without it a
/// reply is indistinguishable from a probe, so the peer that receives one
/// replies to it, and the first peer replies to THAT. Two clients that
/// successfully punch each other then trade packets as fast as the link allows,
/// for the rest of the session. Every earlier test had zero successful punches,
/// so the first time the mesh actually worked was also the first time it melted.
pub const PACKET_PUNCH: u8 = 0x79;

const PUNCH_PROBE: u8 = 0;
const PUNCH_REPLY: u8 = 1;

/// Both live in the range giuroll's recvfrom hook already swallows
/// (`0x6c < t <= 0x80`), so the game never sees them and needs no teaching.
const _: () = assert!(PACKET_PEER_LIST > 0x6c && PACKET_PEER_LIST <= 0x80);
const _: () = assert!(PACKET_PUNCH > 0x6c && PACKET_PUNCH <= 0x80);

/// How often to re-probe a peer we have not reached yet.
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);

/// Keep probing for this long before accepting that a pair needs the relay.
/// Punching usually succeeds within a handful of probes; carrying on forever
/// would just be noise on a link that is never going to open.
const PUNCH_GIVE_UP: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
pub struct PeerLink {
    /// Where the relay says this peer is.
    told: Option<[u8; 16]>,
    /// Where a punch from this peer actually came FROM.
    ///
    /// Not the same thing as `told`, and this is the one to send to. A NAT
    /// rewrites the source port, and the mapping it opened towards the relay is
    /// not necessarily the mapping it opened towards us. Trusting the relay's
    /// view is the classic way to build a hole punch that works on the
    /// developer's LAN and nowhere else.
    confirmed: Option<[u8; 16]>,
    last_probe: Option<Instant>,
    /// When we last answered this peer, so a burst of probes cannot become a
    /// burst of replies even if the kind byte is ever wrong again.
    last_reply: Option<Instant>,
    first_probe: Option<Instant>,
    probes: u32,
    /// Already reported as unreachable, so the notice is printed once rather
    /// than once per peer list per second.
    skipped: bool,
    /// Same, for a punch whose claimed slot does not match the relay's view.
    mismatch_reported: bool,
}

impl PeerLink {
    const fn new() -> Self {
        Self {
            told: None,
            confirmed: None,
            last_probe: None,
            last_reply: None,
            first_probe: None,
            probes: 0,
            skipped: false,
            mismatch_reported: false,
        }
    }

    pub fn is_direct(&self) -> bool {
        self.confirmed.is_some()
    }

    /// Whether this peer is in the match and therefore owed our input,
    /// by whatever route.
    ///
    /// `told` alone is NOT that question. handle_peer_list deliberately
    /// stores no address for a peer it cannot reach -- that is what stops
    /// us probing it -- so a relay-only peer has `told == None` and is
    /// invisible to any accounting that looks at `told`. It is still in
    /// the match, and the relay copy is its only path.
    pub fn expects_input(&self) -> bool {
        self.told.is_some() || self.skipped
    }
}

pub static mut PEERS: [PeerLink; MAX_PLAYERS] = [PeerLink::new(); MAX_PLAYERS];

/// `[Netplay] enable_mesh`. Off means every pair goes through the relay, as it
/// did before any of this existed -- slower, and the only thing that changes.
///
/// It exists because the mesh is the one part of giuroll that runs ONLY in a 4P
/// session, so when 4P misbehaves and 1v1 does not, this is the switch that
/// says whether the mesh is why.
pub static mut ENABLED: bool = true;

/// Our own slot, so we do not punch ourselves and can label our probes.
pub static mut LOCAL_SLOT: Option<usize> = None;

/// How many peers we have a direct path to, for the stats line and for deciding
/// whether the relay still has to carry a copy.
pub unsafe fn direct_count() -> usize {
    PEERS.iter().filter(|p| p.is_direct()).count()
}

pub unsafe fn reset() {
    PEERS = [PeerLink::new(); MAX_PLAYERS];
    LOCAL_SLOT = None;
}

/// An address we could never reach, and must not probe.
///
/// The relay reports each client by the address ITS socket saw, so an operator
/// playing on the same machine as the relay is announced to everyone else as
/// 127.0.0.1. Probing that from another machine does not merely fail. Nothing
/// is listening on that port locally, the stack answers immediately with ICMP
/// port unreachable, and on Windows the next recvfrom on the socket that sent
/// it fails with WSAECONNRESET -- and that is the GAME's socket, shared with
/// the game's own netplay reads. One useless probe every 100ms is enough to
/// keep knocking the real connection over; it surfaces as giuroll's "recvfrom
/// returned error" and as netplay dropping for no visible reason.
///
/// So such a peer is never probed. That pair stays on the relay, which for a
/// loopback operator is the same physical path a successful punch would have
/// produced anyway -- the relay is already on that machine.
fn unreachable_from_here(ip: [u8; 4]) -> bool {
    // Loopback, "this host", and link-local autoconfiguration. Private ranges
    // are deliberately NOT included: a LAN game is a real and useful case, and
    // there a 192.168.x.x peer is genuinely reachable.
    ip[0] == 127 || ip == [0, 0, 0, 0] || (ip[0] == 169 && ip[1] == 254)
}

fn sockaddr_in(ip_net: [u8; 4], port_net: [u8; 2]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 2; // AF_INET, little-endian u16
    a[1] = 0;
    a[2] = port_net[0];
    a[3] = port_net[1];
    a[4..8].copy_from_slice(&ip_net);
    a
}

fn describe(addr: &[u8; 16]) -> String {
    format!(
        "{}.{}.{}.{}:{}",
        addr[4],
        addr[5],
        addr[6],
        addr[7],
        u16::from_be_bytes([addr[2], addr[3]])
    )
}

/// The relay has told us where everyone is.
pub unsafe fn handle_peer_list(data: &[u8]) {
    if !ENABLED || data.len() < 2 {
        return;
    }
    let count = data[1] as usize;
    let mut off = 2;
    for _ in 0..count {
        if off + 7 > data.len() {
            break;
        }
        let slot = data[off] as usize;
        let ip = [data[off + 1], data[off + 2], data[off + 3], data[off + 4]];
        let port = [data[off + 5], data[off + 6]];
        off += 7;

        if slot >= MAX_PLAYERS || Some(slot) == LOCAL_SLOT {
            continue;
        }

        if unreachable_from_here(ip) {
            if !PEERS[slot].skipped {
                PEERS[slot].skipped = true;
                println!(
                    "giuroll mesh: peer {} is reported at {}.{}.{}.{}, which cannot be reached \
                     from here -- not probing it, that pair stays on the relay",
                    slot, ip[0], ip[1], ip[2], ip[3]
                );
            }
            continue;
        }

        let addr = sockaddr_in(ip, port);
        if PEERS[slot].told != Some(addr) {
            PEERS[slot].told = Some(addr);
            PEERS[slot].first_probe = None;
            PEERS[slot].last_probe = None;
            PEERS[slot].probes = 0;
            println!("giuroll mesh: peer {} is at {}", slot, describe(&addr));
        }
    }
}

/// A punch arrived. Record where it came from -- that address, not the relay's
/// idea of it, is the one that works.
pub unsafe fn handle_punch(data: &[u8], from: *const SOCKADDR) {
    if !ENABLED || data.len() < 2 || from.is_null() {
        return;
    }
    let slot = data[1] as usize;
    if slot >= MAX_PLAYERS || Some(slot) == LOCAL_SLOT {
        return;
    }
    // Packets from before the kind byte existed read as probes.
    let kind = if data.len() >= 3 { data[2] } else { PUNCH_PROBE };

    let addr = *(from as *const [u8; 16]);

    // Does the sender's claimed slot agree with where the relay put that slot?
    //
    // A NAT rewrites the PORT, never the address, so the IP must match even
    // when the port does not -- and a mismatch means the sender is wrong about
    // which seat it occupies. That is not hypothetical: a client that changed
    // seats used to keep announcing its first one, and two peers claiming the
    // same slot made this table flip between their addresses on every packet.
    // Believing it would have routed a player's inputs to somebody else.
    if let Some(told) = PEERS[slot].told {
        if told[4..8] != addr[4..8] {
            if !PEERS[slot].mismatch_reported {
                PEERS[slot].mismatch_reported = true;
                println!(
                    "giuroll mesh: ignoring a punch from {} claiming slot {}, \
                     which the relay places at {} -- that client has a stale slot",
                    describe(&addr),
                    slot,
                    describe(&told)
                );
            }
            return;
        }
    }

    if PEERS[slot].confirmed != Some(addr) {
        PEERS[slot].confirmed = Some(addr);
        println!(
            "giuroll mesh: direct path to peer {} via {} ({} of {} peers direct)",
            slot,
            describe(&addr),
            direct_count(),
            PEERS
                .iter()
                .enumerate()
                .filter(|(i, p)| Some(*i) != LOCAL_SLOT && p.expects_input())
                .count()
        );
    }

    // Answer a PROBE, never a reply. Punching is symmetric -- a probe nobody
    // answers only opens the hole in one direction -- but answering an answer
    // is an unbounded loop between two working peers.
    if kind != PUNCH_PROBE {
        return;
    }

    let now = Instant::now();
    if PEERS[slot]
        .last_reply
        .is_some_and(|t| now.duration_since(t) < PUNCH_INTERVAL)
    {
        return;
    }
    PEERS[slot].last_reply = Some(now);

    if let Some(local) = LOCAL_SLOT {
        let reply = [PACKET_PUNCH, local as u8, PUNCH_REPLY];
        raw_send(&reply, &addr);
    }
}

/// Probe every peer we have an address for but no direct path to yet.
pub unsafe fn tick_punching() {
    if !ENABLED {
        return;
    }
    // Re-read every tick rather than latching the first answer.
    //
    // A seat is not permanent: the chooser releases one with B, and the relay
    // reassigns after a collision. Caching the first non-None answer left a
    // client announcing a seat it no longer held, which is how two peers ended
    // up claiming the same slot.
    let current = crate::replay::four_player_local_slot();

    if current.is_some() && current != LOCAL_SLOT {
        if LOCAL_SLOT.is_some() {
            println!(
                "giuroll mesh: our slot changed {:?} -> {:?}, forgetting every peer",
                LOCAL_SLOT, current
            );
            // Everything in the table was learned as a different player. None
            // of it is safe to keep.
            PEERS = [PeerLink::new(); MAX_PLAYERS];
        }
        LOCAL_SLOT = current;
    }

    let Some(local) = LOCAL_SLOT else {
        return;
    };
    let now = Instant::now();

    for slot in 0..MAX_PLAYERS {
        if slot == local {
            continue;
        }
        let peer = &mut PEERS[slot];
        if peer.confirmed.is_some() {
            continue;
        }
        let Some(told) = peer.told else {
            continue;
        };

        let first = *peer.first_probe.get_or_insert(now);
        if now.duration_since(first) > PUNCH_GIVE_UP {
            if peer.probes != u32::MAX {
                println!(
                    "giuroll mesh: no direct path to peer {} after {} probes, \
                     staying on the relay for that pair",
                    slot, peer.probes
                );
                peer.probes = u32::MAX;
            }
            continue;
        }
        if peer
            .last_probe
            .is_some_and(|t| now.duration_since(t) < PUNCH_INTERVAL)
        {
            continue;
        }

        peer.last_probe = Some(now);
        peer.probes = peer.probes.saturating_add(1);
        let probe = [PACKET_PUNCH, local as u8, PUNCH_PROBE];
        raw_send(&probe, &told);
    }
}

/// Send one battle packet to everyone who needs it.
///
/// Returns true when every peer was reached directly, meaning the caller can
/// skip the relay entirely.
pub unsafe fn send_to_peers(data: &[u8]) -> bool {
    if !ENABLED {
        return false;
    }
    let Some(local) = LOCAL_SLOT else {
        return false;
    };

    let mut expected = 0;
    let mut reached = 0;
    for slot in 0..MAX_PLAYERS {
        if slot == local {
            continue;
        }
        // A peer we deliberately never probed still has to be fed.
        //
        // THIS IS THE FIRST-BATTLE STALL. Counting only peers with a
        // `told` address left a relay-only peer out of `expected`
        // entirely, so a sender whose every OTHER peer was direct got
        // reached == expected, returned true, and skipped the relay copy
        // that was the missing peer's only route.
        //
        // Live 2026-09-08: the operator played on the relay's own machine,
        // so everyone was told slot 0 was at 127.0.0.1 and correctly
        // refused to probe it. Slot 1 had direct paths to slots 2 and 3,
        // counted 2 of 2, and never sent slot 0 a single input. Slot 0
        // stalled at frame 9 with nothing from slot 1, and slots 2 and 3
        // then stalled at 17 waiting on slot 0.
        if !PEERS[slot].expects_input() {
            continue;
        }
        expected += 1;
        if let Some(addr) = PEERS[slot].confirmed {
            raw_send(data, &addr);
            reached += 1;
        }
    }

    expected > 0 && reached == expected
}

/// Windows reports an ICMP error on a UDP socket by failing the next RECEIVE.
///
/// That is the mechanism this whole module has to be careful of. Sending to a
/// destination that answers with ICMP port-unreachable does not fail the send:
/// it fails the next `recvfrom` on that socket with WSAECONNRESET -- and the
/// socket here is shared with the game's own netplay. One useless probe is
/// enough to make the GAME's read fail, which it reads as the connection
/// dropping. giuroll's own "WARNING: recvfrom returned error." is that error
/// arriving.
///
/// Wine emulates this Windows behaviour deliberately, so a Linux player gets it
/// too -- and gets it worse, because a probe to a local port with nothing on it
/// produces ICMP instantly and reliably, where a probe across the internet is
/// usually just dropped by a firewall with no reply at all.
///
/// SIO_UDP_CONNRESET is the standard way off: it is what UDP servers set so a
/// dead peer cannot break their receive loop. Turning it off here means nothing
/// the mesh sends can ever break the game's reads, whatever it is aimed at.
const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

static CONNRESET_QUIETED: AtomicBool = AtomicBool::new(false);

unsafe fn quiet_icmp_errors(socket: SOCKET) {
    if CONNRESET_QUIETED.swap(true, Relaxed) {
        return;
    }

    let mut disable: u32 = 0;
    let mut returned: u32 = 0;

    // Declared here rather than taken from the windows crate: the feature set
    // this build enables does not export WSAIoctl, and ws2_32 is already linked.
    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            s: SOCKET,
            code: u32,
            in_buf: *const std::ffi::c_void,
            in_len: u32,
            out_buf: *mut std::ffi::c_void,
            out_len: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
            completion: *mut std::ffi::c_void,
        ) -> i32;
    }

    let rc = WSAIoctl(
        socket,
        SIO_UDP_CONNRESET,
        &mut disable as *mut u32 as *const std::ffi::c_void,
        std::mem::size_of::<u32>() as u32,
        std::ptr::null_mut(),
        0,
        &mut returned,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );

    println!(
        "giuroll mesh: SIO_UDP_CONNRESET off on the game socket ({})",
        if rc == 0 { "ok" } else { "refused" }
    );
}

/// Send raw bytes on the game's own UDP socket.
///
/// Deliberately the same socket the game already uses, so the NAT mapping our
/// packets travel through is the one the relay saw us on. Opening a second
/// socket would create a second mapping and punch a hole nothing else uses.
unsafe fn raw_send(data: &[u8], to: &[u8; 16]) {
    let netmanager = *(0x8986a0 as *const usize);
    if netmanager == 0 {
        return;
    }
    let socket = netmanager + 0x3e4;
    let handle = *ptr_wrap!(socket as *const SOCKET);

    // Before the first probe ever leaves, and not after: the whole point is
    // that the game's reads must never see the fallout from ours.
    quiet_icmp_errors(handle);

    // Some mods such as InfiniteDecks hook the import table of Soku, so this
    // goes through the same resolved pointer send_packet uses.
    let soku_sendto: unsafe extern "stdcall" fn(
        SOCKET,
        *const u8,
        i32,
        i32,
        *const SOCKADDR,
        i32,
    ) -> i32 = std::mem::transmute(0x0081f6c4);

    soku_sendto(
        handle,
        data.as_ptr(),
        data.len() as i32,
        0,
        to.as_ptr() as *const SOCKADDR,
        0x10,
    );
}
