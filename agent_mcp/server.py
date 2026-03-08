"""
nostr-agent-mcp — MCP server giving AI agents a persistent Nostr identity
and encrypted peer-to-peer messaging.

MCP tools exposed:
  agent_whoami        — return this agent's pubkey, npub, and manifest
  agent_publish_profile — publish/update this agent's kind 0 profile on Nostr
  agent_discover      — find other AI agents by capability or DVM kind
  agent_dm_send       — send a NIP-44 encrypted DM to any Nostr pubkey
  agent_dm_read       — read and decrypt incoming DMs
  agent_dm_send_with_payment — send a DM that includes a Lightning payment

Claude Desktop config (~/.config/claude/claude_desktop_config.json):

    {
      "mcpServers": {
        "nostr-agent": {
          "command": "uvx",
          "args": ["nostr-agent-mcp"],
          "env": {
            "NOSTR_NSEC": "nsec1...",
            "NWC_CONNECTION_STRING": "nostr+walletconnect://..."
          }
        }
      }
    }

Any agent with this config gets a stable Nostr identity and can reach any
other agent running this server — without any central server or account.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .crypto import load_privkey, pubkey_from_privkey
from .identity import (
    _encode_npub,
    build_agent_manifest,
    discover_agents,
    fetch_agent_profile,
    publish_manifest,
)
from .messaging import receive_dms, send_dm, send_dm_with_payment

mcp = FastMCP(
    "nostr-agent-mcp",
    instructions=(
        "Gives this AI agent a persistent Nostr identity and encrypted "
        "peer-to-peer messaging with other agents. Use agent_whoami to see "
        "your identity, agent_discover to find peer agents, and agent_dm_send "
        "to communicate privately with them."
    ),
)


# ---------------------------------------------------------------------------
# Identity tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def agent_whoami() -> dict:
    """
    Return this agent's Nostr identity: pubkey (hex), npub (bech32), and
    the agent manifest (if published). This is the agent's persistent
    cryptographic identity — stable across sessions and hardware.

    Returns:
        pubkey:  32-byte hex public key
        npub:    bech32-encoded public key (npub1...)
        profile: the kind 0 manifest from Nostr relays (or null if not yet published)
    """
    privkey = load_privkey()
    pubkey = pubkey_from_privkey(privkey)
    npub = _encode_npub(pubkey)

    # Try to fetch existing profile
    profile = None
    try:
        profile = await asyncio.wait_for(fetch_agent_profile(pubkey), timeout=5.0)
    except Exception:
        pass

    return {
        "pubkey": pubkey,
        "npub": npub,
        "nostr_uri": f"nostr:{npub}",
        "profile": profile,
    }


@mcp.tool()
async def agent_publish_profile(
    name: str,
    about: str,
    lud16: Optional[str] = None,
    website: Optional[str] = None,
    capabilities: Optional[list[str]] = None,
    mcp_servers: Optional[list[str]] = None,
    dvm_kinds: Optional[list[int]] = None,
) -> dict:
    """
    Publish or update this agent's Nostr identity manifest (kind 0 profile).

    This announces the agent to the network — other agents can discover it
    by capability, hire it via DM, and build reputation attestations.

    Parameters:
        name:         Agent name (e.g. "Balthazar")
        about:        Short description of what this agent does
        lud16:        Lightning address for payments (e.g. "agent@getalby.com")
        website:      Homepage or GitHub URL
        capabilities: List of capability tags (e.g. ["code", "bitcoin", "nostr"])
        mcp_servers:  MCP server names this agent has installed
        dvm_kinds:    NIP-90 DVM job kinds this agent can process

    Returns the published event ID and the agent's npub.
    """
    event = build_agent_manifest(
        name=name,
        about=about,
        lud16=lud16 or os.environ.get("LIGHTNING_ADDRESS", ""),
        website=website,
        capabilities=capabilities or [],
        mcp_servers=mcp_servers or [],
        dvm_kinds=dvm_kinds or [],
    )
    await publish_manifest(event)
    npub = _encode_npub(event["pubkey"])
    return {
        "event_id": event["id"],
        "pubkey": event["pubkey"],
        "npub": npub,
        "nostr_uri": f"nostr:{npub}",
        "status": "published",
    }


# ---------------------------------------------------------------------------
# Discovery tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def agent_discover(
    capability: Optional[str] = None,
    dvm_kind: Optional[int] = None,
    limit: int = 10,
) -> list[dict]:
    """
    Discover other AI agents on Nostr.

    Scans Nostr relays for kind 0 profiles that contain an `agent` field
    (the convention used by nostr-agent-mcp). Returns a list of agents
    with their capabilities, Lightning address, and how to contact them.

    Parameters:
        capability: Filter by capability (e.g. "bitcoin", "code", "nostr")
        dvm_kind:   Filter by NIP-90 job kind offered (e.g. 5100, 5202)
        limit:      Maximum number of agents to return (default 10)

    Returns list of:
        pubkey, npub, name, about, lud16, agent manifest
    """
    agents = await discover_agents(
        capability=capability,
        dvm_kind=dvm_kind,
        limit=limit,
        timeout=12.0,
    )
    return agents


@mcp.tool()
async def agent_fetch_profile(pubkey_or_npub: str) -> Optional[dict]:
    """
    Fetch the Nostr profile of a specific agent by pubkey (hex) or npub.

    Returns the full profile content including the `agent` manifest if present.
    Returns null if the profile is not found on relays.
    """
    # Decode npub to hex if needed
    if pubkey_or_npub.startswith("npub1"):
        pubkey = _npub_to_hex(pubkey_or_npub)
    else:
        pubkey = pubkey_or_npub

    return await fetch_agent_profile(pubkey, timeout=8.0)


# ---------------------------------------------------------------------------
# Messaging tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def agent_dm_send(
    recipient_pubkey: str,
    message: str,
    reply_to: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """
    Send a NIP-44 encrypted direct message to another agent.

    The message is encrypted with ChaCha20-Poly1305 using ECDH key agreement —
    only the recipient can decrypt it. The relay sees metadata (who talks to
    whom, when) but never the message content.

    Parameters:
        recipient_pubkey: hex pubkey of the recipient agent (or npub1...)
        message:          plaintext message to send
        reply_to:         optional event_id this message replies to
        metadata:         optional dict for agent-specific structured data

    Returns the published event ID.

    Example use cases:
    - Ask a peer agent to collaborate on a task
    - Request a quote for a NIP-90 DVM job
    - Share a result privately
    - Negotiate terms before a Lightning payment
    """
    if recipient_pubkey.startswith("npub1"):
        recipient_pubkey = _npub_to_hex(recipient_pubkey)

    event_id = await send_dm(
        recipient_pubkey,
        message,
        reply_to=reply_to,
        metadata=metadata,
    )
    return {"event_id": event_id, "status": "sent"}


@mcp.tool()
async def agent_dm_send_with_payment(
    recipient_pubkey: str,
    message: str,
    sats: int,
) -> dict:
    """
    Send an encrypted DM that includes a Lightning payment.

    Creates a Lightning invoice for `sats`, embeds it in the encrypted
    message envelope, and sends the DM. The recipient can read the message
    and redeem the sats. Useful for paying peer agents for completed work,
    tipping for information, or sending a payment with context.

    Parameters:
        recipient_pubkey: hex pubkey of the recipient (or npub1...)
        message:          message to accompany the payment
        sats:             amount in satoshis

    Returns event_id, bolt11 invoice (if wallet connected), and sats amount.
    """
    if recipient_pubkey.startswith("npub1"):
        recipient_pubkey = _npub_to_hex(recipient_pubkey)

    result = await send_dm_with_payment(
        recipient_pubkey,
        message,
        sats,
    )
    return result


@mcp.tool()
async def agent_dm_read(
    limit: int = 20,
    since_minutes_ago: Optional[int] = None,
) -> list[dict]:
    """
    Read and decrypt incoming direct messages addressed to this agent.

    Fetches NIP-44 encrypted DMs from Nostr relays and decrypts them.
    Messages that can't be decrypted (wrong key, different format) are
    silently skipped.

    Parameters:
        limit:              Max messages to return (default 20)
        since_minutes_ago:  Only fetch messages from the last N minutes
                            (default: last 24 hours)

    Returns list of messages with:
        event_id, sender_pubkey, sender_npub, created_at (unix),
        text, sats (optional), bolt11 (optional), reply_to (optional)
    """
    since = None
    if since_minutes_ago is not None:
        since = int(time.time()) - (since_minutes_ago * 60)
    else:
        since = int(time.time()) - 86400  # last 24h default

    messages = []
    async for dm in receive_dms(since=since, limit=limit, timeout=8.0):
        messages.append(dm)
    return messages


# ---------------------------------------------------------------------------
# npub decoding helper
# ---------------------------------------------------------------------------

def _npub_to_hex(npub: str) -> str:
    """Decode npub1... bech32 to hex pubkey."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    _, data_part = npub.lower().split("1", 1)
    decoded = [CHARSET.index(c) for c in data_part[:-6]]

    # Remove witness version byte, convert 5-bit to 8-bit
    decoded = decoded[1:]  # drop witness version
    acc, bits, result = 0, 0, []
    for val in decoded:
        acc = (acc << 5) | val
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((acc >> bits) & 0xFF)
    return bytes(result[:32]).hex()


def main() -> None:
    mcp.run(transport="stdio")
