//! Client transaction-ID idempotence for `/send`, `/redact`, and
//! `/sendToDevice` (node-local; cross-node txn dedup arrives with M4
//! clustering).
//!
//! Transaction IDs are scoped to the device AND the endpoint path (spec
//! v1.7): the same txn ID against a different room or event type is a new
//! transaction. Event-producing endpoints cache the event ID they minted
//! so a retry returns the same one; `/sendToDevice` has nothing to return
//! and only needs the transaction marked as handled.
//!
//! The cache also remembers the reverse direction — which device minted
//! an event under which txn ID — so /sync and /event can stamp
//! `unsigned.transaction_id` on the local echo for that device only.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use ruma::OwnedEventId;

const CAP: usize = 16 * 1024;

/// `None` = handled with no event ID to replay (`/sendToDevice`).
type Entries = HashMap<String, Option<OwnedEventId>>;
/// event ID -> (user, device, txn) of the /send that minted it.
type Echo = HashMap<String, (String, String, String)>;

#[derive(Default)]
pub struct TxnCache {
    inner: Mutex<(Entries, VecDeque<String>, Echo)>,
}

impl TxnCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(user_id: &str, device_id: &str, scope: &str, txn_id: &str) -> String {
        format!("{user_id}\0{device_id}\0{scope}\0{txn_id}")
    }

    pub fn get(
        &self,
        user_id: &str,
        device_id: &str,
        scope: &str,
        txn_id: &str,
    ) -> Option<OwnedEventId> {
        let inner = self.inner.lock().expect("txn lock poisoned");
        inner
            .0
            .get(&Self::key(user_id, device_id, scope, txn_id))
            .cloned()
            .flatten()
    }

    /// Whether the transaction was handled at all (with or without an
    /// event ID).
    pub fn seen(&self, user_id: &str, device_id: &str, scope: &str, txn_id: &str) -> bool {
        let inner = self.inner.lock().expect("txn lock poisoned");
        inner
            .0
            .contains_key(&Self::key(user_id, device_id, scope, txn_id))
    }

    pub fn put(
        &self,
        user_id: &str,
        device_id: &str,
        scope: &str,
        txn_id: &str,
        event_id: OwnedEventId,
    ) {
        let mut inner = self.inner.lock().expect("txn lock poisoned");
        inner.2.insert(
            event_id.as_str().to_owned(),
            (user_id.to_owned(), device_id.to_owned(), txn_id.to_owned()),
        );
        Self::insert(
            &mut inner,
            Self::key(user_id, device_id, scope, txn_id),
            Some(event_id),
        );
    }

    /// Mark a transaction handled without an event ID (`/sendToDevice`).
    pub fn mark(&self, user_id: &str, device_id: &str, scope: &str, txn_id: &str) {
        let mut inner = self.inner.lock().expect("txn lock poisoned");
        Self::insert(
            &mut inner,
            Self::key(user_id, device_id, scope, txn_id),
            None,
        );
    }

    /// Local echo: stamp `unsigned.transaction_id` on an event served back
    /// to the device that sent it.
    pub fn stamp_echo(&self, ev: &mut serde_json::Value, user_id: &str, device_id: &str) {
        let Some(event_id) = ev.get("event_id").and_then(|v| v.as_str()) else {
            return;
        };
        let inner = self.inner.lock().expect("txn lock poisoned");
        let Some((u, d, txn)) = inner.2.get(event_id) else {
            return;
        };
        if u == user_id && d == device_id {
            let txn = txn.clone();
            drop(inner);
            ev["unsigned"]["transaction_id"] = txn.into();
        }
    }

    fn insert(
        inner: &mut (Entries, VecDeque<String>, Echo),
        key: String,
        event_id: Option<OwnedEventId>,
    ) {
        if inner.0.insert(key.clone(), event_id).is_none() {
            inner.1.push_back(key);
            if inner.1.len() > CAP {
                if let Some(old) = inner.1.pop_front() {
                    if let Some(Some(evicted)) = inner.0.remove(&old) {
                        inner.2.remove(evicted.as_str());
                    }
                }
            }
        }
    }
}
