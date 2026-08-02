#!/usr/bin/env python3
"""E2EE interop smoke — the M5 exit criterion, made executable.

Alice (matrix-nio on Synapse) and bob (matrix-nio on saltator) exchange
Megolm-encrypted messages in a federated room. Everything the encryption
depends on runs over the real wire: cross-server device-key queries and
one-time-key claims, room-key sharing via federated to-device messages,
and the encrypted events themselves.

Usage: e2ee_smoke.py <synapse-base-url> <saltator-base-url>
Users @alice:synapse / @bob:saltator must already exist (run.sh creates
them); this logs in fresh devices.
"""

import asyncio
import sys
import tempfile

from nio import (
    AsyncClient,
    AsyncClientConfig,
    EnableEncryptionBuilder,
    LoginResponse,
    RoomCreateResponse,
    RoomMessageText,
)

SYN, SAL = sys.argv[1], sys.argv[2]
ALICE_MSG = "e2ee hello from alice on synapse"
BOB_MSG = "e2ee hello back from bob on saltator"


def client(base: str, user: str) -> AsyncClient:
    cfg = AsyncClientConfig(encryption_enabled=True, store_sync_tokens=True)
    return AsyncClient(base, user, store_path=tempfile.mkdtemp(), config=cfg)


async def sync_until(c: AsyncClient, pred, what: str, timeout: float = 120.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        resp = await c.sync(timeout=1000)
        if pred():
            return
        await asyncio.sleep(0.5)
    raise AssertionError(f"timed out waiting for: {what} (last sync: {resp})")


async def main() -> None:
    alice = client(SYN, "@alice:synapse")
    bob = client(SAL, "@bob:saltator")

    r = await alice.login("alicepass")
    assert isinstance(r, LoginResponse), f"alice login failed: {r}"
    r = await bob.login("bobpass")
    assert isinstance(r, LoginResponse), f"bob login failed: {r}"

    # First syncs make nio publish device keys + one-time keys.
    await alice.sync(timeout=0)
    await bob.sync(timeout=0)

    # Alice creates an encrypted room and invites bob across federation.
    r = await alice.room_create(
        invite=["@bob:saltator"],
        initial_state=[EnableEncryptionBuilder().as_dict()],
    )
    assert isinstance(r, RoomCreateResponse), f"room_create failed: {r}"
    room_id = r.room_id
    print(f"encrypted room: {room_id}", flush=True)

    await sync_until(bob, lambda: room_id in bob.invited_rooms, "bob's invite")
    join = await bob.join(room_id)
    print(f"bob join: {join}", flush=True)
    await sync_until(bob, lambda: room_id in bob.rooms, "bob's join")
    await sync_until(
        alice,
        lambda: room_id in alice.rooms and "@bob:saltator" in alice.rooms[room_id].users,
        "alice seeing bob join",
    )
    assert alice.rooms[room_id].encrypted, "room not flagged encrypted for alice"
    assert bob.rooms[room_id].encrypted, "room not flagged encrypted for bob"

    got_alice, got_bob = [], []
    alice.add_event_callback(
        lambda room, ev: got_alice.append(ev.body) if room.room_id == room_id else None,
        RoomMessageText,
    )
    bob.add_event_callback(
        lambda room, ev: got_bob.append(ev.body) if room.room_id == room_id else None,
        RoomMessageText,
    )

    # Synapse -> saltator: alice encrypts to bob's device (device keys
    # queried and one-time key claimed through Synapse over federation;
    # the Megolm session rides a federated to-device message).
    r = await alice.room_send(
        room_id,
        "m.room.message",
        {"msgtype": "m.text", "body": ALICE_MSG},
        ignore_unverified_devices=True,
    )
    print(f"alice send: {r}", flush=True)
    await sync_until(bob, lambda: ALICE_MSG in got_bob, "bob decrypting alice's message")

    # saltator -> Synapse: the same loop driven from our side.
    r = await bob.room_send(
        room_id,
        "m.room.message",
        {"msgtype": "m.text", "body": BOB_MSG},
        ignore_unverified_devices=True,
    )
    print(f"bob send: {r}", flush=True)
    await sync_until(alice, lambda: BOB_MSG in got_alice, "alice decrypting bob's message")

    await alice.close()
    await bob.close()
    print("E2EE round trip verified", flush=True)


asyncio.run(main())
