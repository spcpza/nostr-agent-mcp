"""
Agent identity — Nostr kind 0 profile with an `agent` extension field.

The agent manifest is stored as a Nostr kind 0 event on relays. Any Nostr
client renders it as a normal profile. AI agents that understand the `agent`
field can use it for capability discovery, hiring, and peer trust.

Manifest schema (stored in kind 0 content JSON):
{
  "name":        "Balthazar",
  "about":       "Autonomous AI agent — Bitcoin infrastructure builder",
  "lud16":       "sensiblefield821792@getalby.com",    ← Lightning address
  "website":     "https://github.com/spcpza",
  "agent": {
    "version":      1,
    "model_family": "claude",                           ← inference family
    "capabilities": ["code", "bitcoin", "nostr", "dvm"],
    "mcp_servers":  ["bitcoin-mcp", "nostr-agent-mcp"],
    "dvm_kinds":    [5100, 5202, 5250],                 ← NIP-90 kinds offered
    "hire":         "nostr:npub1...",                   ← DM this npub to hire
    "donate":       "sensiblefield821792@getalby.com",
    "created_at":   1709900000
  }
}

This is a convention, not a new NIP — it extends existing kind 0 profiles.
Any agent that reads kind 0 profiles from Nostr and understands the `agent`
field gets full discovery for free.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from .crypto import load_privkey, pubkey_from_privkey, sign_event

_DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]


def build_agent_manifest(
    *,
    name: str,
    about: str,
    lud16: Optional[str] = None,
    website: Optional[str] = None,
    model_family: str = "claude",
    capabilities: list[str] | None = None,
    mcp_servers: list[str] | None = None,
    dvm_kinds: list[int] | None = None,
    privkey_hex: Optional[str] = None,
) -> dict:
    """
    Build (but don't publish) a kind 0 agent profile event.

    Returns the signed Nostr event dict ready to be published.
    """
    privkey = load_privkey(privkey_hex)
    pubkey = pubkey_from_privkey(privkey)
    npub = _encode_npub(pubkey)

    content = {
        "name": name,
        "about": about,
        "agent": {
            "version": 1,
            "model_family": model_family,
            "capabilities": capabilities or [],
            "mcp_servers": mcp_servers or [],
            "dvm_kinds": dvm_kinds or [],
            "hire": f"nostr:{npub}",
            "created_at": int(time.time()),
        },
    }
    if lud16:
        content["lud16"] = lud16
    if website:
        content["website"] = website

    return sign_event(0, json.dumps(content, separators=(",", ":")), [], privkey)


async def publish_manifest(
    event: dict,
    relays: list[str] | None = None,
) -> None:
    """Publish a signed kind 0 event to Nostr relays."""
    from .relay import RelayPool
    async with RelayPool(relays or _DEFAULT_RELAYS) as pool:
        await pool.publish(event)


async def fetch_agent_profile(
    pubkey_hex: str,
    *,
    relays: list[str] | None = None,
    timeout: float = 8.0,
) -> Optional[dict]:
    """
    Fetch the kind 0 profile for an agent pubkey.

    Returns the parsed content dict (with 'agent' field if present),
    or None if not found.
    """
    from .relay import RelayPool
    async with RelayPool(relays or _DEFAULT_RELAYS) as pool:
        filt = {"kinds": [0], "authors": [pubkey_hex], "limit": 1}
        async for event in pool.subscribe(filt, timeout=timeout):
            try:
                return json.loads(event.get("content", "{}"))
            except json.JSONDecodeError:
                return None
    return None


async def discover_agents(
    *,
    capability: Optional[str] = None,
    dvm_kind: Optional[int] = None,
    relays: list[str] | None = None,
    timeout: float = 12.0,
    limit: int = 20,
) -> list[dict]:
    """
    Discover other AI agents on Nostr by scanning kind 0 profiles with
    an `agent` field.

    Parameters
    ----------
    capability: Filter by capability string (e.g. "bitcoin", "code").
    dvm_kind:   Filter by NIP-90 DVM kind offered (e.g. 5100).
    timeout:    Seconds to scan relays.
    limit:      Max number of agents to return.

    Returns a list of dicts:
        pubkey, name, about, lud16, agent (the nested agent manifest dict)
    """
    from .relay import RelayPool
    agents = []

    async with RelayPool(relays or _DEFAULT_RELAYS) as pool:
        # We can't filter by content on the relay, so we fetch recent kind 0s
        # and filter locally. In practice a relay index would be needed for
        # large-scale discovery — this is the MVP approach.
        filt = {"kinds": [0], "limit": 200}
        async for event in pool.subscribe(filt, timeout=timeout):
            try:
                content = json.loads(event.get("content", "{}"))
            except json.JSONDecodeError:
                continue

            if "agent" not in content:
                continue  # not an AI agent profile

            agent_meta = content["agent"]

            # Apply filters
            if capability and capability not in agent_meta.get("capabilities", []):
                continue
            if dvm_kind and dvm_kind not in agent_meta.get("dvm_kinds", []):
                continue

            agents.append({
                "pubkey": event.get("pubkey", ""),
                "name": content.get("name", ""),
                "about": content.get("about", ""),
                "lud16": content.get("lud16", ""),
                "npub": _encode_npub(event.get("pubkey", "")),
                "agent": agent_meta,
            })

            if len(agents) >= limit:
                break

    return agents


# ---------------------------------------------------------------------------
# npub bech32 encoding (display only)
# ---------------------------------------------------------------------------

def _encode_npub(pubkey_hex: str) -> str:
    """Encode a hex pubkey as npub1... bech32."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    hrp = "npub"
    data = bytes.fromhex(pubkey_hex)

    # Convert 8-bit bytes to 5-bit groups
    acc, bits, result = 0, 0, []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            result.append((acc >> bits) & 31)

    if bits:
        result.append((acc << (5 - bits)) & 31)

    # Compute checksum
    def _polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                if (b >> i) & 1: chk ^= GEN[i]
        return chk

    hrp_data = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    witver = [1] + result  # witness version 1 for npub
    check = _polymod(hrp_data + witver + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(check >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[x] for x in witver + checksum)
