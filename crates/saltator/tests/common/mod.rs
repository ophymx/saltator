//! Helpers shared by this crate's integration tests.
#![allow(dead_code)] // each test binary uses a subset

use std::net::{SocketAddr, TcpListener};
use std::sync::Mutex;

/// An address nothing is listening on, and that this test binary has not
/// already handed out.
///
/// Binding `:0` and dropping the listener leaves the port free — which is
/// the point, since the server under test binds it itself — but the port
/// also goes straight back to the ephemeral pool, so a sibling test
/// running in parallel can be handed the same number moments later. The
/// loser of that race dies with `Address already in use`, and the test
/// waiting on it reports a timeout rather than the real cause.
///
/// That is not hypothetical: it took down a CI run on the e2e suite, and
/// four threads taking four ports each by plain bind-and-drop reproduce
/// it within a couple of hundred iterations.
///
/// Remembering what has been issued closes it, because every port in a
/// given test binary comes from here. It does not (and need not) cover
/// separate processes: `cargo test` runs test binaries one at a time.
pub fn ephemeral_addr() -> SocketAddr {
    static TAKEN: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    for _ in 0..100 {
        let addr = TcpListener::bind("127.0.0.1:0")
            .expect("bind an ephemeral port")
            .local_addr()
            .expect("read the bound address");
        let mut taken = TAKEN.lock().expect("port registry");
        if !taken.contains(&addr.port()) {
            taken.push(addr.port());
            return addr;
        }
    }
    panic!("no unused ephemeral port after 100 attempts");
}

/// [`ephemeral_addr`], when only the port number is wanted.
pub fn free_port() -> u16 {
    ephemeral_addr().port()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant the helper exists for. If someone simplifies it back
    /// to a plain bind-and-drop, this is what notices.
    ///
    /// The draw count is deliberate. A single round of four threads taking
    /// four ports each — the shape of a parallel test binary — only
    /// reproduces a duplicate about one time in twenty, so a guard that
    /// cheap would wave the regression through most of the time. Repeating
    /// the round pushes that to a near-certainty while staying two
    /// thousand `bind`/`close` pairs, which costs milliseconds.
    #[test]
    fn ephemeral_addrs_are_never_handed_out_twice() {
        let seen = Mutex::new(Vec::new());
        for _ in 0..128 {
            std::thread::scope(|s| {
                for _ in 0..4 {
                    s.spawn(|| {
                        let mine: Vec<u16> = (0..4).map(|_| ephemeral_addr().port()).collect();
                        seen.lock().expect("seen").extend(mine);
                    });
                }
            });
        }
        let mut ports = seen.into_inner().expect("seen");
        let total = ports.len();
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), total, "a port was handed out more than once");
    }
}
