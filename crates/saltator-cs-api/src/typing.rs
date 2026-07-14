//! Ephemeral typing state: shard-leader memory only, lost on failover by
//! design (spec.md §5.5).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

#[derive(Default)]
struct RoomTyping {
    /// user → expiry.
    users: HashMap<String, Instant>,
    /// Generation of the last change to this room's typing set.
    changed_at: u64,
}

/// Per-room typing users with expiry, a global change generation (so sync
/// tokens can window typing updates), and a wake channel for `/sync`
/// long-polls.
pub struct TypingMap {
    inner: Mutex<HashMap<String, RoomTyping>>,
    gen: AtomicU64,
    wake: broadcast::Sender<()>,
}

impl TypingMap {
    pub fn new() -> Self {
        let (wake, _) = broadcast::channel(64);
        Self {
            inner: Mutex::new(HashMap::new()),
            gen: AtomicU64::new(0),
            wake,
        }
    }

    /// Wakes whenever any room's typing set changes.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.wake.subscribe()
    }

    /// Generation of the latest change (sync token component).
    pub fn generation(&self) -> u64 {
        self.gen.load(Ordering::Acquire)
    }

    pub fn set(&self, room_id: &str, user_id: &str, typing: bool, timeout: Duration) {
        let mut inner = self.inner.lock().expect("typing lock poisoned");
        let room = inner.entry(room_id.to_owned()).or_default();
        let changed = if typing {
            room.users
                .insert(user_id.to_owned(), Instant::now() + timeout)
                .is_none()
        } else {
            room.users.remove(user_id).is_some()
        };
        if changed {
            room.changed_at = self.gen.fetch_add(1, Ordering::AcqRel) + 1;
            drop(inner);
            let _ = self.wake.send(());
        }
    }

    /// Users currently typing in a room and the room's last-change
    /// generation. Expiry counts as a change.
    pub fn typing_in(&self, room_id: &str) -> (Vec<String>, u64) {
        let mut inner = self.inner.lock().expect("typing lock poisoned");
        let Some(room) = inner.get_mut(room_id) else {
            return (Vec::new(), 0);
        };
        let now = Instant::now();
        let before = room.users.len();
        room.users.retain(|_, expires| *expires > now);
        if room.users.len() != before {
            room.changed_at = self.gen.fetch_add(1, Ordering::AcqRel) + 1;
        }
        let mut users: Vec<String> = room.users.keys().cloned().collect();
        users.sort();
        (users, room.changed_at)
    }
}

impl Default for TypingMap {
    fn default() -> Self {
        Self::new()
    }
}
