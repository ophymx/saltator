//! Node-local registry of running shard Raft groups, keyed by group
//! number. The internal RPC server routes incoming Raft messages through
//! it (spec.md §8: all shard groups multiplex over one control channel).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use openraft::Raft;

use crate::TypeConfig;

#[derive(Clone, Default)]
pub struct ShardRegistry {
    groups: Arc<RwLock<HashMap<u64, Raft<TypeConfig>>>>,
}

impl ShardRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, group: u64, raft: Raft<TypeConfig>) {
        self.groups
            .write()
            .expect("shard registry lock poisoned")
            .insert(group, raft);
    }

    pub fn deregister(&self, group: u64) {
        self.groups
            .write()
            .expect("shard registry lock poisoned")
            .remove(&group);
    }

    pub fn get(&self, group: u64) -> Option<Raft<TypeConfig>> {
        self.groups
            .read()
            .expect("shard registry lock poisoned")
            .get(&group)
            .cloned()
    }
}
