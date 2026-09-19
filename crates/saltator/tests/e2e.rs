//! Two users chat on a single-node Saltator over real HTTP — the
//! compiled binary, real sockets, plus restart persistence. The
//! broadest test in the tree: everything else stubs something.

use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{json, Value};

struct Node {
    child: Child,
    base: String,
}

impl Node {
    fn spawn(config_path: &std::path::Path, client_port: u16) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_saltator"))
            .args(["start", "--config"])
            .arg(config_path)
            .spawn()
            .expect("failed to spawn saltator");
        Self {
            child,
            base: format!("http://127.0.0.1:{client_port}"),
        }
    }

    async fn wait_ready(&mut self) {
        let client = reqwest::Client::new();
        for _ in 0..300 {
            // A daemon that failed to start will never answer, and waiting
            // the full 30s for that tells you nothing. Notice it died and
            // say so — its own stderr has already explained why.
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("saltator exited before becoming ready: {status}");
            }
            if let Ok(resp) = client
                .get(format!("{}/_matrix/client/versions", self.base))
                .send()
                .await
            {
                if resp.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("saltator did not become ready within 30s");
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A port nothing is listening on, and that this test binary has not
/// already handed out.
///
/// Binding `:0` and dropping the listener leaves the port free — which
/// is the point, since the daemon binds it — but the port also goes
/// straight back to the ephemeral pool, so a sibling test running in
/// parallel can be handed the same number. That is not hypothetical:
/// it is what made `metrics_listener_exports_a_running_node` fail in
/// CI with `Address already in use`, after which the daemon exited and
/// the test sat waiting 30s for a process that was gone.
///
/// Remembering what has been issued closes it, because every port in
/// this binary comes from here.
fn free_port() -> u16 {
    static TAKEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    for _ in 0..100 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut taken = TAKEN.lock().expect("port registry");
        if !taken.contains(&port) {
            taken.push(port);
            return port;
        }
    }
    panic!("could not find an unused port");
}

/// The single-node config every e2e test shares, maintained once.
/// `metrics_port` adds the metrics listener line; `appservice_dir`
/// points `[client]` at a registration directory; everything else is
/// the same node shape.
fn write_config(
    dir: &tempfile::TempDir,
    server_name: &str,
    client_port: u16,
    metrics_port: Option<u16>,
    appservice_dir: Option<&std::path::Path>,
) -> std::path::PathBuf {
    let internal_port = free_port();
    let federation_port = free_port();
    let metrics_line = metrics_port
        .map(|p| format!("metrics = \"127.0.0.1:{p}\"\n"))
        .unwrap_or_default();
    let appservice_line = appservice_dir
        .map(|p| format!("appservice_registration_dir = '{}'\n", p.display()))
        .unwrap_or_default();
    let config_path = dir.path().join("saltator.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
server_name = "{server_name}"
data_dir = '{data}'

[node]
id = 1
advertise = "127.0.0.1:{internal_port}"

[listeners]
internal = "127.0.0.1:{internal_port}"
client = "127.0.0.1:{client_port}"
federation = "127.0.0.1:{federation_port}"
{metrics_line}
[client]
default_room_version = "12"
{appservice_line}"#,
            data = dir.path().join("data").display(),
        ),
    )
    .unwrap();
    config_path
}

async fn register(client: &reqwest::Client, base: &str, user: &str, password: &str) -> String {
    let url = format!("{base}/_matrix/client/v3/register");
    let resp: Value = client
        .post(&url)
        .json(&json!({"username": user, "password": password}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = resp["session"].as_str().expect("UIA challenge");
    let resp: Value = client
        .post(&url)
        .json(&json!({
            "username": user,
            "password": password,
            "auth": {"type": "m.login.dummy", "session": session},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("registration failed: {resp}"))
        .to_owned()
}

#[tokio::test]
async fn two_element_shaped_users_chat_and_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let client_port = free_port();
    let config_path = write_config(&dir, "e2e.test", client_port, None, None);

    let mut node = Node::spawn(&config_path, client_port);
    node.wait_ready().await;
    let http = reqwest::Client::new();
    let base = node.base.clone();

    // Two users register and chat.
    let alice = register(&http, &base, "alice", "alice-pw").await;
    let bob = register(&http, &base, "bob", "bob-pw").await;

    let room: Value = http
        .post(format!("{base}/_matrix/client/v3/createRoom"))
        .bearer_auth(&alice)
        .json(&json!({"name": "E2E", "invite": ["@bob:e2e.test"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // Bob waits for the invite via long-poll sync, then joins.
    let mut since = String::new();
    for _ in 0..100 {
        let url = if since.is_empty() {
            format!("{base}/_matrix/client/v3/sync")
        } else {
            format!("{base}/_matrix/client/v3/sync?since={since}&timeout=2000")
        };
        let resp: Value = http
            .get(url)
            .bearer_auth(&bob)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        since = resp["next_batch"].as_str().unwrap().to_owned();
        if resp["rooms"]["invite"].get(&room_id).is_some() {
            break;
        }
    }
    let resp = http
        .post(format!("{base}/_matrix/client/v3/rooms/{room_id}/join"))
        .bearer_auth(&bob)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{:?}", resp.text().await);

    // Messages flow both ways.
    for (token, txn, body) in [(&alice, "t1", "hello bob"), (&bob, "t2", "hello alice")] {
        let resp = http
            .put(format!(
                "{base}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"
            ))
            .bearer_auth(token)
            .json(&json!({"msgtype": "m.text", "body": body}))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }
    let sync: Value = http
        .get(format!("{base}/_matrix/client/v3/sync"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let timeline = sync["rooms"]["join"][&room_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    let bodies: Vec<&str> = timeline
        .iter()
        .filter_map(|e| e["content"]["body"].as_str())
        .collect();
    assert!(bodies.contains(&"hello bob") && bodies.contains(&"hello alice"));

    // Restart: sessions, rooms, and history survive (signing key now
    // lives encrypted in the metadata group).
    node.stop();
    let mut node = Node::spawn(&config_path, client_port);
    node.wait_ready().await;

    let sync: Value = http
        .get(format!("{base}/_matrix/client/v3/sync"))
        .bearer_auth(&bob)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let timeline = sync["rooms"]["join"][&room_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert!(timeline
        .iter()
        .any(|e| e["content"]["body"] == "hello alice"));

    // And the room still accepts events after recovery.
    let resp = http
        .put(format!(
            "{base}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/t3"
        ))
        .bearer_auth(&alice)
        .json(&json!({"msgtype": "m.text", "body": "still here"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{:?}", resp.text().await);

    node.stop();
}

/// The exporter against a REAL node: recorder installed before the shards
/// start, the layer on the client router, the sampler ticking. Each of
/// those is wired in `main` and nowhere else, so a unit test cannot see
/// any of them — this is the only place the wiring is proven.
#[tokio::test]
async fn metrics_listener_exports_a_running_node() {
    let dir = tempfile::tempdir().unwrap();
    let client_port = free_port();
    let metrics_port = free_port();
    let config_path = write_config(&dir, "metrics.test", client_port, Some(metrics_port), None);

    let mut node = Node::spawn(&config_path, client_port);
    node.wait_ready().await;
    let http = reqwest::Client::new();
    let base = node.base.clone();

    // Traffic worth measuring: a registration (which proposes to the user
    // shard) and a room creation (which proposes to the room shard).
    let alice = register(&http, &base, "alice", "alice-pw").await;
    let created: Value = http
        .post(format!("{base}/_matrix/client/v3/createRoom"))
        .bearer_auth(&alice)
        .json(&json!({"preset": "private_chat"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(created["room_id"].is_string(), "{created}");

    let scrape_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    // The gauge tick is on a 10s interval and the first one fires
    // immediately, but the node may still have been mid-election then, so
    // leadership is polled rather than assumed.
    let mut scrape = String::new();
    for _ in 0..100 {
        scrape = http
            .get(&scrape_url)
            .send()
            .await
            .expect("metrics listener answers")
            .text()
            .await
            .unwrap();
        if scrape.contains(r#"saltator_shard_leader{keyspace="room",shard="0"} 1"#) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // HTTP: the route template, not the path, and the surface label that
    // separates this from federation traffic.
    assert!(
        scrape.contains(r#"route="/_matrix/client/v3/createRoom",status="200""#),
        "{scrape}"
    );
    assert!(scrape.contains(r#"surface="client""#), "{scrape}");
    // Shard: both keyspaces that just took a write, labeled as spec.md §7
    // asks — keyspace and shard. A fresh cluster runs the default 16
    // room shards and the created room hashes to one of them, so the
    // assertion is on the label SHAPE, not a particular index.
    assert!(
        scrape.lines().any(|l| l
            .starts_with(r#"saltator_shard_proposals_total{keyspace="room",shard=""#)
            && l.contains(r#"outcome="local""#)),
        "{scrape}"
    );
    assert!(
        scrape.contains(r#"saltator_shard_applied_entries_total{keyspace="user",shard="0"}"#),
        "{scrape}"
    );
    // Sampled gauges: this single node leads its own groups, including the
    // metadata group, which has no sequence of its own to report.
    assert!(
        scrape.contains(r#"saltator_shard_leader{keyspace="meta",shard="0"} 1"#),
        "{scrape}"
    );
    assert!(
        !scrape.contains(r#"saltator_shard_seq{keyspace="meta""#),
        "the metadata group has no app sequence to report:\n{scrape}"
    );
    // Process identity, for joining a regression to the version it arrived in.
    assert!(scrape.contains("saltator_build_info{version="), "{scrape}");
    assert!(scrape.contains("saltator_uptime_seconds"), "{scrape}");

    // No account, room, or event identifier may appear anywhere in a
    // scrape. This is the cardinality rule as an executable assertion —
    // it fails the moment somebody adds a label carrying user input.
    for forbidden in ["alice", "@alice:metrics.test", "!"] {
        assert!(
            !scrape.contains(forbidden),
            "{forbidden:?} leaked into metrics:\n{scrape}"
        );
    }

    node.stop();
}

/// A registered appservice against the real daemon: registration file
/// loading in main, ghost registration + masquerade through the wire,
/// the ping round trip, and the outbound push worker delivering a
/// transaction (with the `hs_token`) to the AS's listener.
#[tokio::test]
async fn appservice_bridge_against_a_running_node() {
    use axum::extract::{Path as AxPath, State as AxState};

    // The stub bridge: records transactions and pings.
    type Log = std::sync::Arc<tokio::sync::Mutex<Vec<(String, Value, Option<String>)>>>;
    let txns: Log = Default::default();
    let pings: Log = Default::default();
    async fn put_txn(
        AxState((txns, _)): AxState<(Log, Log)>,
        AxPath(txn_id): AxPath<String>,
        headers: axum::http::HeaderMap,
        axum::Json(body): axum::Json<Value>,
    ) -> axum::Json<Value> {
        let bearer = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::to_owned);
        txns.lock().await.push((txn_id, body, bearer));
        axum::Json(json!({}))
    }
    async fn post_ping(
        AxState((_, pings)): AxState<(Log, Log)>,
        axum::Json(body): axum::Json<Value>,
    ) -> axum::Json<Value> {
        pings.lock().await.push((String::new(), body, None));
        axum::Json(json!({}))
    }
    let app = axum::Router::new()
        .route(
            "/_matrix/app/v1/transactions/{txn_id}",
            axum::routing::put(put_txn),
        )
        .route("/_matrix/app/v1/ping", axum::routing::post(post_ping))
        .with_state((txns.clone(), pings.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // A real registration file, as a bridge would ship it.
    let dir = tempfile::tempdir().unwrap();
    let as_dir = dir.path().join("appservices");
    std::fs::create_dir_all(&as_dir).unwrap();
    std::fs::write(
        as_dir.join("bridge.yaml"),
        format!(
            concat!(
                "id: bridge\n",
                "url: {url}\n",
                "as_token: e2e-as-token\n",
                "hs_token: e2e-hs-token\n",
                "sender_localpart: bridgebot\n",
                "namespaces:\n",
                "  users:\n",
                "  - exclusive: true\n",
                "    regex: '@tg_.*'\n",
            ),
            url = stub_url
        ),
    )
    .unwrap();

    let client_port = free_port();
    let config_path = write_config(&dir, "as.test", client_port, None, Some(&as_dir));
    let mut node = Node::spawn(&config_path, client_port);
    node.wait_ready().await;
    let http = reqwest::Client::new();
    let base = node.base.clone();

    // Ping: the daemon can reach the bridge.
    let resp: Value = http
        .post(format!("{base}/_matrix/client/v1/appservice/bridge/ping"))
        .bearer_auth("e2e-as-token")
        .json(&json!({"transaction_id": "hello"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(resp["duration_ms"].is_u64(), "{resp}");
    assert_eq!(pings.lock().await.len(), 1);

    // Ghost + room + a masqueraded message.
    let resp: Value = http
        .post(format!("{base}/_matrix/client/v3/register"))
        .bearer_auth("e2e-as-token")
        .json(&json!({"type": "m.login.application_service", "username": "tg_alice"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["user_id"], "@tg_alice:as.test", "{resp}");
    let room: Value = http
        .post(format!("{base}/_matrix/client/v3/createRoom"))
        .bearer_auth("e2e-as-token")
        .json(&json!({"invite": ["@tg_alice:as.test"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let room_enc = room_id.replace('!', "%21").replace(':', "%3A");
    let st = http
        .post(format!(
            "{base}/_matrix/client/v3/rooms/{room_enc}/join?user_id=@tg_alice:as.test"
        ))
        .bearer_auth("e2e-as-token")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(st.status().is_success(), "{}", st.text().await.unwrap());
    let sent: Value = http
        .put(format!(
            "{base}/_matrix/client/v3/rooms/{room_enc}/send/m.room.message/t1?user_id=@tg_alice:as.test&ts=4242"
        ))
        .bearer_auth("e2e-as-token")
        .json(&json!({"msgtype": "m.text", "body": "over the bridge"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let event_id = sent["event_id"].as_str().unwrap().to_owned();

    // The push worker (leader-gated, durable cursor) delivers it.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let txns = txns.lock().await;
        if let Some((_, body, bearer)) = txns.iter().find(|(_, body, _)| {
            body["events"]
                .as_array()
                .is_some_and(|evs| evs.iter().any(|e| e["event_id"] == event_id.as_str()))
        }) {
            assert_eq!(bearer.as_deref(), Some("e2e-hs-token"));
            let ev = body["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["event_id"] == event_id.as_str())
                .unwrap();
            assert_eq!(ev["content"]["body"], "over the bridge");
            assert_eq!(ev["sender"], "@tg_alice:as.test");
            assert_eq!(ev["origin_server_ts"], 4242, "?ts massaging held");
            break;
        }
        drop(txns);
        assert!(
            std::time::Instant::now() < deadline,
            "transaction never reached the bridge"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node.stop();
}
