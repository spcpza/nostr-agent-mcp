"""
End-to-end integration tests for nostr-agent-mcp.

These tests connect to real Nostr relays and verify the full flow:
  1. Generate two fresh keypairs (Alice and Bob)
  2. Alice sends Bob a NIP-44 encrypted DM
  3. Bob subscribes and decrypts it
  4. Verify content matches

Run with: python3 -m pytest tests/test_e2e.py -v -s
"""

import asyncio
import time
import uuid
import pytest

from agent_mcp.crypto import generate_privkey, pubkey_from_privkey, nip44_encrypt, nip44_decrypt, sign_event
from agent_mcp.relay import RelayPool
from agent_mcp.identity import _encode_npub, build_agent_manifest
from agent_mcp.messaging import send_dm, receive_dms

# Use multiple relays so tests survive any single relay being down
TEST_RELAYS = [
    "wss://nos.lol",
    "wss://nostr.mom",
    "wss://relay.primal.net",
]
DM_KIND = 17


@pytest.mark.asyncio
async def test_relay_connection():
    """Can we connect to at least one relay?"""
    async with RelayPool(TEST_RELAYS) as pool:
        assert len(pool._conns) >= 1
        print(f"\n  ✓ Connected to {len(pool._conns)}/{len(TEST_RELAYS)} relays")


@pytest.mark.asyncio
async def test_relay_subscribe_recent_events():
    """Can we fetch any recent events from the relay?"""
    events = []
    async with RelayPool(TEST_RELAYS) as pool:
        filt = {"kinds": [1], "limit": 3}
        async for event in pool.subscribe(filt, timeout=8.0):
            events.append(event)
            if len(events) >= 3:
                break

    assert len(events) >= 1, "Should receive at least 1 event from relay"
    print(f"\n  ✓ Received {len(events)} events from relay")
    for e in events:
        assert "id" in e
        assert "pubkey" in e
        assert "kind" in e


@pytest.mark.asyncio
async def test_publish_and_fetch_profile():
    """Publish a kind 0 agent profile and fetch it back."""
    priv = generate_privkey()
    pub = pubkey_from_privkey(priv)
    npub = _encode_npub(pub)

    # Build and publish
    event = build_agent_manifest(
        name="TestAgent",
        about="Integration test agent — ignore",
        capabilities=["test"],
        privkey_hex=priv,
    )

    async with RelayPool(TEST_RELAYS) as pool:
        await pool.publish(event)
        print(f"\n  ✓ Published kind 0 profile: {npub[:20]}...")

    # Fetch back — give relays time to index (some are slow)
    await asyncio.sleep(4.0)

    from agent_mcp.identity import fetch_agent_profile
    profile = await fetch_agent_profile(pub, relays=TEST_RELAYS, timeout=8.0)

    assert profile is not None, "Should be able to fetch published profile"
    assert profile.get("name") == "TestAgent"
    assert "agent" in profile
    assert "test" in profile["agent"]["capabilities"]
    print(f"  ✓ Fetched profile back: name={profile['name']}, capabilities={profile['agent']['capabilities']}")


@pytest.mark.asyncio
async def test_encrypted_dm_roundtrip():
    """
    Full end-to-end DM test:
      Alice → encrypts with NIP-44 → publishes kind 17 → relay
      Bob   → subscribes → receives → decrypts → reads plaintext
    """
    alice_priv = generate_privkey()
    alice_pub = pubkey_from_privkey(alice_priv)
    bob_priv = generate_privkey()
    bob_pub = pubkey_from_privkey(bob_priv)

    unique_token = f"test-{uuid.uuid4()}"
    message = f"Hello Bob! This is a secret message. Token: {unique_token}"
    since = int(time.time()) - 30  # generous lookback window

    print(f"\n  Alice: {_encode_npub(alice_pub)[:20]}...")
    print(f"  Bob:   {_encode_npub(bob_pub)[:20]}...")
    print(f"  Sending: {message!r}")

    # Alice sends
    event_id = await send_dm(
        bob_pub,
        message,
        metadata={"test": True, "timestamp": since},
        relays=TEST_RELAYS,
        privkey_hex=alice_priv,
    )
    print(f"  ✓ DM published: event {event_id[:16]}...")

    await asyncio.sleep(4.0)  # relay propagation

    # Bob reads
    received = []
    async for dm in receive_dms(
        since=since,
        limit=10,
        relays=TEST_RELAYS,
        privkey_hex=bob_priv,
        timeout=10.0,
    ):
        received.append(dm)

    # Filter to our specific message by token
    ours = [dm for dm in received if unique_token in dm.get("text", "")]

    assert len(ours) >= 1, (
        f"Bob should receive at least 1 matching DM. "
        f"Got {len(received)} total DMs, none matching token {unique_token!r}"
    )

    dm = ours[0]
    print(f"  ✓ Bob decrypted: {dm['text']!r}")
    assert dm["text"] == message
    assert dm["sender_pubkey"] == alice_pub
    assert dm["meta"] == {"test": True, "timestamp": since}
    print(f"  ✓ Sender verified: {dm['sender_npub'][:20]}...")
    print(f"  ✓ Metadata intact: {dm['meta']}")


@pytest.mark.asyncio
async def test_dm_wrong_key_cannot_decrypt():
    """Carol cannot decrypt a DM addressed to Bob."""
    alice_priv = generate_privkey()
    bob_priv = generate_privkey()
    bob_pub = pubkey_from_privkey(bob_priv)
    carol_priv = generate_privkey()

    since = int(time.time()) - 30
    unique_token = f"secret-{uuid.uuid4()}"

    await send_dm(bob_pub, f"Private message {unique_token}", relays=TEST_RELAYS, privkey_hex=alice_priv)
    await asyncio.sleep(3.0)

    # Carol tries to read Bob's DMs (she won't see any addressed to Bob,
    # because relays filter by #p tag — but even if she received the raw
    # event, she couldn't decrypt it)
    carol_received = []
    async for dm in receive_dms(since=since, limit=10, relays=TEST_RELAYS, privkey_hex=carol_priv, timeout=6.0):
        carol_received.append(dm)

    # Carol's DM inbox should not contain Bob's message
    carol_tokens = [dm for dm in carol_received if unique_token in dm.get("text", "")]
    assert len(carol_tokens) == 0, "Carol should not be able to read Bob's DMs"
    print(f"\n  ✓ Carol's inbox has {len(carol_received)} DMs, none of Bob's private messages")


@pytest.mark.asyncio
async def test_agent_discover():
    """Publish a profile and verify it appears in agent_discover results."""
    priv = generate_privkey()
    pub = pubkey_from_privkey(priv)
    unique_cap = f"test-cap-{uuid.uuid4().hex[:8]}"

    event = build_agent_manifest(
        name="DiscoverTestAgent",
        about="Temporary test agent for discovery integration test",
        capabilities=[unique_cap, "test"],
        dvm_kinds=[5999],
        privkey_hex=priv,
    )

    async with RelayPool(TEST_RELAYS) as pool:
        await pool.publish(event)

    await asyncio.sleep(4.0)

    from agent_mcp.identity import discover_agents
    agents = await discover_agents(
        capability=unique_cap,
        relays=TEST_RELAYS,
        timeout=10.0,
    )

    found = [a for a in agents if a["pubkey"] == pub]
    assert len(found) >= 1, f"Should discover published agent by capability {unique_cap!r}"
    print(f"\n  ✓ Discovered agent: {found[0]['name']} capabilities={found[0]['agent']['capabilities']}")
