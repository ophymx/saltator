//! Client transaction-ID idempotence for `/send` and `/redact`
//! (node-local; cross-node txn dedup arrives with M4 clustering).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use ruma::OwnedEventId;

const CAP: usize = 16 * 1024;

#[derive(Default)]
pub struct TxnCache {
    inner: Mutex<(HashMap<String, OwnedEventId>, VecDeque<String>)>,
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
        inner.0.get(&Self::key(user_id, device_id, txn_id)).cloned()
    }

    pub fn put(&self, user_id: &str, device_id: &str, txn_id: &str, event_id: OwnedEventId) {
        let mut inner = self.inner.lock().expect("txn lock poisoned");
        let key = Self::key(user_id, device_id, txn_id);
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
