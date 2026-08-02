//! Ephemeral presence state: like typing (spec.md §5.5), this lives in
//! node memory and resets on restart — clients re-establish it on their
//! next sync.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use tokio::sync::broadcast;

#[derive(Clone)]
pub struct PresenceEntry {
    pub presence: String,
    pub status_msg: Option<String>,
    pub last_active: Instant,
    /// Generation of the last observable change (sync token window).
    pub changed_at: u64,
}

/// A snapshot handed to readers: entry plus the owning user.
#[derive(Clone)]
pub struct PresenceSnapshot {
    pub user_id: String,
    pub entry: PresenceEntry,
}

/// Hard cap on tracked users. Inbound federation `m.presence` EDUs carry
/// remote-controlled user ids, so without a bound a malicious server could
/// grow this map without limit (and every `/sync` scans it). At the cap we
/// evict the least-recently-active users.
const MAX_PRESENCE_USERS: usize = 50_000;

/// Per-user presence with a global change generation and a wake channel
/// for `/sync` long-polls — the same shape as [`crate::TypingMap`].
pub struct PresenceMap {
    inner: Mutex<HashMap<String, PresenceEntry>>,
    gen: AtomicU64,
    wake: broadcast::Sender<()>,
}

impl PresenceMap {
    pub fn new() -> Self {
        let (wake, _) = broadcast::channel(64);
        Self {
            inner: Mutex::new(HashMap::new()),
            gen: AtomicU64::new(0),
            wake,
        }
    }

    /// Wakes whenever any user's presence changes.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.wake.subscribe()
    }

    /// Generation of the latest change (sync token component).
    pub fn generation(&self) -> u64 {
        self.gen.load(Ordering::Acquire)
    }

    /// Set presence from an explicit PUT. `status_msg: None` clears any
    /// previous message (the spec treats the field as whole-state).
    pub fn set(&self, user_id: &str, presence: &str, status_msg: Option<String>) {
        self.update(user_id, presence, Some(status_msg));
    }

    /// Set presence as a side effect of `/sync?set_presence=`; the status
    /// message is left as-is.
    pub fn set_active(&self, user_id: &str, presence: &str) {
        self.update(user_id, presence, None);
    }

    fn update(&self, user_id: &str, presence: &str, status_msg: Option<Option<String>>) {
        let mut inner = self.inner.lock().expect("presence lock poisoned");
        let now = Instant::now();
        let changed;
        {
            let entry = inner
                .entry(user_id.to_owned())
                .or_insert_with(|| PresenceEntry {
                    presence: String::new(),
                    status_msg: None,
                    last_active: now,
                    changed_at: 0,
                });
            let mut c = entry.presence != presence;
            entry.presence = presence.to_owned();
            entry.last_active = now;
            if let Some(msg) = status_msg {
                c |= entry.status_msg != msg;
                entry.status_msg = msg;
            }
            if c {
                entry.changed_at = self.gen.fetch_add(1, Ordering::AcqRel) + 1;
            }
            changed = c;
        }
        // Bound the table: evict least-recently-active users once over the
        // cap. Runs only at the cap (amortized O(1)); the just-touched user
        // has the newest timestamp and is never the one evicted.
        if inner.len() > MAX_PRESENCE_USERS {
            let target = MAX_PRESENCE_USERS * 9 / 10;
            let evict = inner.len() - target;
            let mut times: Vec<Instant> = inner.values().map(|e| e.last_active).collect();
            times.select_nth_unstable(evict);
            let cutoff = times[evict];
            inner.retain(|_, e| e.last_active >= cutoff);
        }
        drop(inner);
        if changed {
            let _ = self.wake.send(());
        }
    }

    pub fn get(&self, user_id: &str) -> Option<PresenceEntry> {
        self.inner
            .lock()
            .expect("presence lock poisoned")
            .get(user_id)
            .cloned()
    }

    /// All entries that changed after `since_gen`.
    pub fn changed_since(&self, since_gen: u64) -> Vec<PresenceSnapshot> {
        self.inner
            .lock()
            .expect("presence lock poisoned")
            .iter()
            .filter(|(_, e)| e.changed_at > since_gen)
            .map(|(user_id, entry)| PresenceSnapshot {
                user_id: user_id.clone(),
                entry: entry.clone(),
            })
            .collect()
    }
}

impl Default for PresenceMap {
    fn default() -> Self {
        Self::new()
    }
}
