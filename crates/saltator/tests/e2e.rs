//! M2 exit criterion (spec.md §12): two users chat on a single-node
//! Saltator over real HTTP — the compiled binary, real sockets, plus
//! restart persistence.

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

    async fn wait_ready(&self) {
        let client = reqwest::Client::new();
        for _ in 0..300 {
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
        panic!("saltator did not become ready");
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    let internal_port = free_port();
    let federation_port = free_port();
    let config_path = dir.path().join("saltator.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
server_name = "e2e.test"
data_dir = "{data}"

[node]
id = 1
advertise = "127.0.0.1:{internal_port}"

[listeners]
internal = "127.0.0.1:{internal_port}"
client = "127.0.0.1:{client_port}"
federation = "127.0.0.1:{federation_port}"

[client]
default_room_version = "12"
"#,
            data = dir.path().join("data").display(),
        ),
    )
    .unwrap();

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
