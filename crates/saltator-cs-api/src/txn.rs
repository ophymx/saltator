//! Client transaction-ID idempotence for `/send`, `/redact`, and
//! `/sendToDevice` (node-local; cross-node txn dedup arrives with M4
//! clustering).
//!
//! Event-producing endpoints cache the event ID they minted so a retry
//! returns the same one; `/sendToDevice` has nothing to return and only
//! needs the transaction marked as handled.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use ruma::OwnedEventId;

const CAP: usize = 16 * 1024;

/// `None` = handled with no event ID to replay (`/sendToDevice`).
type Entries = HashMap<String, Option<OwnedEventId>>;

#[derive(Default)]
pub struct TxnCache {
    inner: Mutex<(Entries, VecDeque<String>)>,
}

impl TxnCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(user_id: &str, device_id: &str, txn_id: &str) -> String {
        format!("{user_id}\0{device_id}\0{txn_id}")
    }

    pub fn get(&self, user_id: &str, device_id: &str, txn_id: &str) -> Option<OwnedEventId> {
        let inner = self.inner.lock().expect("txn lock poisoned");
        inner
            .0
            .get(&Self::key(user_id, device_id, txn_id))
            .cloned()
            .flatten()
    }

    /// Whether the transaction was handled at all (with or without an
    /// event ID).
    pub fn seen(&self, user_id: &str, device_id: &str, txn_id: &str) -> bool {
        let inner = self.inner.lock().expect("txn lock poisoned");
        inner.0.contains_key(&Self::key(user_id, device_id, txn_id))
    }

    pub fn put(&self, user_id: &str, device_id: &str, txn_id: &str, event_id: OwnedEventId) {
        self.insert(Self::key(user_id, device_id, txn_id), Some(event_id));
    }

    /// Mark a transaction handled without an event ID (`/sendToDevice`).
    pub fn mark(&self, user_id: &str, device_id: &str, txn_id: &str) {
        self.insert(Self::key(user_id, device_id, txn_id), None);
    }

    fn insert(&self, key: String, event_id: Option<OwnedEventId>) {
        let mut inner = self.inner.lock().expect("txn lock poisoned");
        if inner.0.insert(key.clone(), event_id).is_none() {
            inner.1.push_back(key);
            if inner.1.len() > CAP {
                if let Some(old) = inner.1.pop_front() {
                    inner.0.remove(&old);
                }
            }
        }
    }
}
