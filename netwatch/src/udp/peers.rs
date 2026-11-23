//! Connected per-peer sockets beside the main UDP socket, for Apple platforms
//! and Linux.
//!
//! # Apple
//!
//! XNU's `udp_output` connects and disconnects the protocol control block
//! around every send that names a destination: a route lookup plus two
//! rehashes of the global UDP PCB table under its lock, per datagram. On Apple
//! silicon that is 25-40 µs per datagram, five times the cost of the send
//! itself, and it is the ceiling on a QUIC data path that sends one `sendmsg`
//! per packet. Batching with `sendmsg_x` does not amortize it; only a socket
//! `connect(2)`ed to the peer avoids it (a connected send costs ~5 µs, and a
//! connected receive about half of an unconnected one).
//!
//! # Linux
//!
//! A multi-queue NIC with XPS (the default: one transmit queue per CPU) picks
//! the queue of every datagram sent on an unconnected socket from the CPU the
//! sending thread happens to run on. A QUIC connection's sends move between
//! runtime worker threads, so consecutive batches leave on different queues
//! and overtake each other, and on virtio the peer's replies are steered to
//! whichever receive queue last transmitted, so the other direction reorders
//! too. An IP tunnel hands that reordering to the inner TCP flow, which takes
//! it for loss: between two 6-queue virtio VMs it cost about 40% of the
//! throughput (1.0 against 1.65 Gbit/s). The kernel remembers a socket's
//! transmit queue only while the socket holds a cached route, which a
//! `connect(2)`ed UDP socket does and an unconnected one never does
//! (`__netdev_pick_tx` calls `sk_tx_queue_set` only with `sk_dst_cache`
//! set). A connected socket therefore keeps a peer's datagrams on one queue,
//! in order, wherever the sender runs.
//!
//! # Mechanism
//!
//! The main socket must stay unconnected (it talks to every peer and every
//! probe target), so a peer that receives sustained traffic gets its own
//! socket: bound with `SO_REUSEPORT` to the main socket's address and port,
//! then connected to the peer. The kernel steers datagrams *from* that peer to
//! the connected socket (an exact four-tuple match beats the wildcard
//! binding), and everything else still arrives on the main socket, so the
//! peer sockets must be polled for receive alongside it. From the peer's point
//! of view nothing changes: the same local port sends and receives.
//!
//! A receive returns one socket's batch, and the sockets take turns at it:
//! the one after the socket that delivered the last batch is asked first, the
//! main socket included. Asked in a fixed order, a socket that stays readable
//! (one peer sending faster than the caller reads) would keep every socket
//! behind it from being read until their buffers overflowed.
//!
//! Promotion happens after [`PROMOTE_AFTER`] sends to one destination within
//! [`PROMOTE_WINDOW`], which hole-punch probes and a handshake stay well
//! under; at most [`MAX_PEERS`]
//! sockets exist, and idle or broken ones are evicted when another is needed.
//! Rebinding the main socket drops them all (they live in the same state).
use std::{
    io,
    net::SocketAddr,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use atomic_waker::AtomicWaker;
use tokio::io::Interest;
use tracing::{debug, trace, warn};

use super::{IpFamily, set_recv_buffer_size, set_send_buffer_size};

/// Sends to one destination within [`PROMOTE_WINDOW`] before it gets a
/// connected socket: a flow, not the trickle of probes a reconnect loop sends
/// to every candidate address.
const PROMOTE_AFTER: u32 = 64;
/// Sends older than this no longer count towards promotion.
const PROMOTE_WINDOW: Duration = Duration::from_secs(1);
/// Upper bound on connected peer sockets per main socket. Larger on Linux,
/// where the main socket is typically a server's and every busy client
/// beyond the bound keeps reordering.
#[cfg(target_vendor = "apple")]
const MAX_PEERS: usize = 8;
#[cfg(not(target_vendor = "apple"))]
const MAX_PEERS: usize = 64;
/// Destinations tracked towards promotion.
const MAX_CANDIDATES: usize = 32;
/// A peer socket with no send for this long is evicted when room is needed.
const IDLE_EVICT: Duration = Duration::from_secs(60);

pub(super) struct PeerSocket {
    addr: SocketAddr,
    socket: tokio::net::UdpSocket,
    state: noq_udp::UdpSocketState,
    /// Milliseconds since the owning [`PeerSockets`] was created.
    last_send: AtomicU64,
    /// Receive hit an error that is not transient: skip it until evicted.
    broken: AtomicBool,
}

pub(super) struct PeerSockets {
    /// The main socket's bound address (its family, port and interface).
    local: SocketAddr,
    created: Instant,
    peers: RwLock<Vec<PeerSocket>>,
    /// Recent send counts for destinations without a peer socket: the count
    /// and when it started.
    candidates: Mutex<Vec<(SocketAddr, u32, Instant)>>,
    /// The receiver last seen in [`poll_recv`](Self::poll_recv), woken when a
    /// peer socket is added: a receive already pending is registered only on
    /// the sockets that existed when it polled, and the kernel steers the
    /// peer's replies to the new one as soon as it exists.
    recv_waker: AtomicWaker,
    /// The socket whose turn it is to deliver the next received batch: 0 is
    /// the main socket, `i + 1` the peer at index `i` (see the module docs).
    recv_turn: AtomicUsize,
}

impl std::fmt::Debug for PeerSockets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let peers = self.peers.read().unwrap();
        f.debug_struct("PeerSockets")
            .field("local", &self.local)
            .field("peers", &peers.iter().map(|p| p.addr).collect::<Vec<_>>())
            .finish()
    }
}

impl PeerSockets {
    pub(super) fn new(local: SocketAddr) -> Self {
        Self {
            local,
            created: Instant::now(),
            peers: RwLock::new(Vec::new()),
            candidates: Mutex::new(Vec::new()),
            recv_waker: AtomicWaker::new(),
            recv_turn: AtomicUsize::new(0),
        }
    }

    /// Whether the next receive is the main socket's to deliver, rather than
    /// a peer socket's.
    pub(super) fn main_recv_turn(&self) -> bool {
        self.recv_turn.load(Ordering::Relaxed) == 0
    }

    /// The main socket delivered a batch: the peer sockets go next.
    pub(super) fn note_main_recv(&self) {
        self.recv_turn.store(1, Ordering::Relaxed);
    }

    fn now_ms(&self) -> u64 {
        self.created.elapsed().as_millis() as u64
    }

    /// Sends `transmit` on the connected socket for its destination, if one
    /// exists. `None` means the caller sends on the main socket. A send the
    /// kernel would block on falls back the same way rather than waiting: UDP
    /// sends on Apple fail with `ENOBUFS` instead of blocking and Linux's
    /// forced 7 MiB send buffer rarely fills, so this is rare, and the main
    /// socket's readiness is what the caller polls.
    pub(super) fn send(&self, transmit: &noq_udp::Transmit<'_>) -> Option<io::Result<()>> {
        let peers = self.peers.read().unwrap();
        let peer = peers.iter().find(|p| p.addr == transmit.destination)?;
        peer.last_send.store(self.now_ms(), Ordering::Relaxed);
        #[cfg(target_vendor = "apple")]
        let res = peer.state.send_connected((&peer.socket).into(), transmit);
        // Linux accepts a destination on a connected socket, and the batched
        // (GSO) send path names one.
        // TODO: `send` is deprecated, but `try_send` surfaces all I/O errors, which noq treats as fatal.
        #[cfg(not(target_vendor = "apple"))]
        #[allow(deprecated)]
        let res = peer.state.send((&peer.socket).into(), transmit);
        match res {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
            res => Some(res),
        }
    }

    /// Records a send on the main socket to `dst` and promotes `dst` to a
    /// connected socket once it has seen [`PROMOTE_AFTER`] of them. Called
    /// only on the main-socket path, so a promoted destination costs nothing
    /// further here.
    pub(super) fn note_main_send(&self, dst: SocketAddr) {
        if IpFamily::from(dst.ip()) != IpFamily::from(self.local.ip()) {
            return;
        }
        let promote = {
            let now = Instant::now();
            let mut candidates = self.candidates.lock().unwrap();
            match candidates.iter_mut().find(|(addr, ..)| *addr == dst) {
                Some((_, count, since)) => {
                    if now.duration_since(*since) > PROMOTE_WINDOW {
                        *count = 0;
                        *since = now;
                    }
                    *count += 1;
                    *count >= PROMOTE_AFTER
                }
                None => {
                    if candidates.len() >= MAX_CANDIDATES {
                        candidates.remove(0);
                    }
                    candidates.push((dst, 1, now));
                    false
                }
            }
        };
        if !promote {
            return;
        }
        self.candidates
            .lock()
            .unwrap()
            .retain(|(addr, ..)| *addr != dst);
        let peer = match self.connect(dst) {
            Ok(peer) => peer,
            Err(err) => {
                warn!(%dst, "failed to open a connected peer socket: {err:#}");
                return;
            }
        };
        let mut peers = self.peers.write().unwrap();
        if peers.iter().any(|p| p.addr == dst) {
            return;
        }
        let now = self.now_ms();
        let idle = IDLE_EVICT.as_millis() as u64;
        peers.retain(|p| {
            let keep = !p.broken.load(Ordering::Relaxed)
                && now.saturating_sub(p.last_send.load(Ordering::Relaxed)) < idle;
            if !keep {
                debug!(peer = %p.addr, "evicting connected peer socket");
            }
            keep
        });
        if peers.len() >= MAX_PEERS {
            let lru = peers
                .iter()
                .enumerate()
                .min_by_key(|(_, p)| p.last_send.load(Ordering::Relaxed))
                .map(|(i, _)| i)
                .expect("non-empty");
            debug!(peer = %peers[lru].addr, "evicting least recently used connected peer socket");
            peers.remove(lru);
        }
        debug!(%dst, local = %self.local, "opened connected peer socket");
        peers.push(peer);
        drop(peers);
        self.recv_waker.wake();
    }

    fn connect(&self, dst: SocketAddr) -> io::Result<PeerSocket> {
        let family = IpFamily::from(self.local.ip());
        let socket = socket2::Socket::new(
            family.into(),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        // Share the main socket's address and port; it set SO_REUSEPORT too.
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;
        if let Err(err) = set_recv_buffer_size(&socket) {
            debug!("failed to set peer socket recv_buffer_size: {err:?}");
        }
        if let Err(err) = set_send_buffer_size(&socket) {
            debug!("failed to set peer socket send_buffer_size: {err:?}");
        }
        if family == IpFamily::V6 {
            socket.set_only_v6(true)?;
        }
        socket.bind(&self.local.into())?;
        socket.set_nonblocking(true)?;
        socket.connect(&dst.into())?;
        let socket = tokio::net::UdpSocket::from_std(socket.into())?;
        let state = noq_udp::UdpSocketState::new((&socket).into())?;
        Ok(PeerSocket {
            addr: dst,
            socket,
            state,
            last_send: AtomicU64::new(self.now_ms()),
            broken: AtomicBool::new(false),
        })
    }

    /// Receives from the first peer socket with data, starting at the one
    /// whose turn it is, and registers `cx` on every one asked that has none.
    /// The caller polls the main socket, before this when the turn is the
    /// main socket's and after it otherwise.
    pub(super) fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.recv_waker.register(cx.waker());
        let peers = self.peers.read().unwrap();
        let len = peers.len();
        // The turn may name a peer that has since been evicted: the modulo
        // below brings it back into range.
        let first = self.recv_turn.load(Ordering::Relaxed).saturating_sub(1);
        for index in (0..len).map(|offset| (first + offset) % len) {
            let peer = &peers[index];
            if peer.broken.load(Ordering::Relaxed) {
                continue;
            }
            loop {
                match peer.socket.poll_recv_ready(cx) {
                    Poll::Pending => break,
                    Poll::Ready(Err(err)) => {
                        if super::is_transient_read_error(&err) || is_peer_unreachable(&err) {
                            continue;
                        }
                        warn!(peer = %peer.addr, "connected peer socket unusable: {err:#}");
                        peer.broken.store(true, Ordering::Relaxed);
                        break;
                    }
                    Poll::Ready(Ok(())) => {}
                }
                let res = peer
                    .socket
                    .try_io(Interest::READABLE, || {
                        peer.state.recv((&peer.socket).into(), bufs, metas)
                    });
                match res {
                    Ok(count) => {
                        trace!(peer = %peer.addr, count, "UDP recv (connected)");
                        // The next peer's turn, or the main socket's after the last.
                        let next = if index + 1 < len { index + 2 } else { 0 };
                        self.recv_turn.store(next, Ordering::Relaxed);
                        return Poll::Ready(Ok(count));
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    // An ICMP unreachable for an earlier send surfaces here on
                    // a connected socket; it says nothing about the socket.
                    Err(err) if super::is_transient_read_error(&err) || is_peer_unreachable(&err) => {
                        continue;
                    }
                    Err(err) => {
                        warn!(peer = %peer.addr, "connected peer socket unusable: {err:#}");
                        peer.broken.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
        Poll::Pending
    }
}

/// `ECONNREFUSED` (ICMP port unreachable) and `EHOSTUNREACH`/`ENETUNREACH`
/// reported against a connected UDP socket describe one earlier datagram.
fn is_peer_unreachable(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable
    )
}
