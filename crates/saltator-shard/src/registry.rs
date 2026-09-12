//! Node-local registry of running shard groups, keyed by group number.
//! The internal RPC server routes incoming Raft messages, remote reads,
//! and remote subscriptions through it (spec.md §8: all shard groups
//! multiplex over one control channel). Holds full [`ShardHandle`]s: the
//! data-plane RPCs need applied-state reads and the change stream, not
//! just the Raft instance.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::handle::ShardHandle;

#[derive(Clone, Default)]
pub struct ShardRegistry {
    groups: Arc<RwLock<HashMap<u64, ShardHandle>>>,
}

impl ShardRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, group: u64, handle: ShardHandle) {
        self.groups
            .write()
            .expect("shard registry lock poisoned")
            .insert(group, handle);
    }

    pub fn deregister(&self, group: u64) {
        self.groups
            .write()
            .expect("shard registry lock poisoned")
            .remove(&group);
    }

    pub fn get(&self, group: u64) -> Option<ShardHandle> {
        self.groups
            .read()
            .expect("shard registry lock poisoned")
            .get(&group)
            .cloned()
    }
}
