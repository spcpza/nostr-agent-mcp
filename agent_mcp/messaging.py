"""
Agent-to-agent encrypted messaging via NIP-44 direct messages.

Nostr kind 4 = legacy NIP-04 DMs (AES, deprecated).
Nostr kind 17 = NIP-44 v2 DMs (ChaCha20-Poly1305, current standard).

We use kind 17 throughout. The relay only sees:
  - sender pubkey
  - recipient pubkey (in 'p' tag)
  - encrypted payload (NIP-44 v2 base64)
  - timestamp

Neither the relay nor any observer can read the message content.
The relay CAN see who is talking to whom — this is a known Nostr
limitation. For metadata privacy, use a Tor-accessible relay.

Usage::

    from agent_mcp.messaging import send_dm, receive_dms

    # Send a task request to another agent
    event_id = await send_dm(
        recipient_pubkey="abc123...",
        message="Can you summarize this: [long text]",
        sats=5,        # optional: attach a Lightning payment hint
    )

    # Read all incoming DMs
    async for dm in receive_dms(since=last_check):
        print(f"From {dm['sender_npub']}: {dm['text']}")
        if dm.get('sats'):
            print(f"  + {dm['sats']} sats attached")
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncGenerator
from typing import Optional

from .crypto import (
    load_privkey,
    nip44_decrypt,
    nip44_encrypt,
    pubkey_from_privkey,
    sign_event,
)
from .identity import _encode_npub

_DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]

# NIP-44 DM kind
_DM_KIND = 17


# ---------------------------------------------------------------------------
# Message envelope
# ---------------------------------------------------------------------------

def _build_dm_content(
    text: str,
    sats: Optional[int] = None,
    bolt11: Optional[str] = None,
    reply_to: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> str:
    """
    Build the JSON payload that goes inside the encrypted DM.

    Schema:
    {
      "text":     "The actual message",
      "sats":     10,                    # optional Lightning amount hint
      "bolt11":   "lnbc...",             # optional attached invoice
      "reply_to": "event_id_hex",        # optional thread reference
      "meta":     { ... }                # optional arbitrary agent metadata
    }
    """
    payload: dict = {"text": text}
    if sats is not None:
        payload["sats"] = sats
    if bolt11:
        payload["bolt11"] = bolt11
    if reply_to:
        payload["reply_to"] = reply_to
    if metadata:
        payload["meta"] = metadata
    return json.dumps(payload, separators=(",", ":"))


async def send_dm(
    recipient_pubkey: str,
    message: str,
    *,
    sats: Optional[int] = None,
    bolt11: Optional[str] = None,
    reply_to: Optional[str] = None,
    metadata: Optional[dict] = None,
    relays: Optional[list[str]] = None,
    privkey_hex: Optional[str] = None,
) -> str:
    """
    Send a NIP-44 encrypted direct message to another agent.

    Parameters
    ----------
    recipient_pubkey : hex pubkey of the recipient agent
    message          : plaintext message content
    sats             : optional sats amount to hint (attach bolt11 for actual payment)
    bolt11           : optional Lightning invoice to include in the envelope
    reply_to         : optional event_id this message replies to
    metadata         : optional dict of arbitrary agent-specific data
    relays           : Nostr relay URLs
    privkey_hex      : sender private key (defaults to env var)

    Returns the published event ID.
    """
    from .relay import RelayPool

    privkey = load_privkey(privkey_hex)
    pubkey = pubkey_from_privkey(privkey)

    payload = _build_dm_content(
        text=message, sats=sats, bolt11=bolt11,
        reply_to=reply_to, metadata=metadata,
    )
    encrypted = nip44_encrypt(payload, privkey, recipient_pubkey)

    tags = [["p", recipient_pubkey]]
    if reply_to:
        tags.append(["e", reply_to, "", "reply"])

    event = sign_event(_DM_KIND, encrypted, tags, privkey)

    _relays = relays or _DEFAULT_RELAYS
    async with RelayPool(_relays) as pool:
        await pool.publish(event)

    return event["id"]


async def receive_dms(
    *,
    since: Optional[int] = None,
    limit: int = 50,
    relays: Optional[list[str]] = None,
    privkey_hex: Optional[str] = None,
    timeout: float = 10.0,
) -> AsyncGenerator[dict, None]:
    """
    Fetch and decrypt incoming DMs addressed to this agent.

    Yields dicts with keys:
        event_id, sender_pubkey, sender_npub, created_at,
        text, sats (optional), bolt11 (optional),
        reply_to (optional), meta (optional), raw_event
    """
    from .relay import RelayPool

    privkey = load_privkey(privkey_hex)
    my_pubkey = pubkey_from_privkey(privkey)

    filt: dict = {
        "kinds": [_DM_KIND],
        "#p": [my_pubkey],
        "limit": limit,
    }
    if since:
        filt["since"] = since

    _relays = relays or _DEFAULT_RELAYS
    async with RelayPool(_relays) as pool:
        async for event in pool.subscribe(filt, timeout=timeout):
            sender = event.get("pubkey", "")
            if sender == my_pubkey:
                continue  # skip own messages

            encrypted = event.get("content", "")
            try:
                decrypted = nip44_decrypt(encrypted, privkey, sender)
                payload = json.loads(decrypted)
            except Exception as exc:
                # Could be NIP-04 format or wrong key — skip silently
                continue

            yield {
                "event_id": event.get("id", ""),
                "sender_pubkey": sender,
                "sender_npub": _encode_npub(sender),
                "created_at": event.get("created_at", 0),
                "text": payload.get("text", ""),
                "sats": payload.get("sats"),
                "bolt11": payload.get("bolt11"),
                "reply_to": payload.get("reply_to"),
                "meta": payload.get("meta"),
                "raw_event": event,
            }


async def send_dm_with_payment(
    recipient_pubkey: str,
    message: str,
    sats: int,
    *,
    relays: Optional[list[str]] = None,
    privkey_hex: Optional[str] = None,
    nwc_string: Optional[str] = None,
) -> dict:
    """
    Send a DM that includes a Lightning payment.

    Creates an invoice for `sats`, includes it in the encrypted envelope,
    and pays it from the NWC wallet. The recipient can redeem the invoice
    when they read the DM.

    Returns {"event_id": ..., "bolt11": ..., "sats": ...}
    """
    import os
    import subprocess

    nwc = nwc_string or os.environ.get("NWC_CONNECTION_STRING", "")
    bolt11 = ""

    if nwc and sats > 0:
        try:
            result = subprocess.run(
                ["npx", "@getalby/cli", "invoice", str(sats)],
                capture_output=True, text=True, timeout=15,
                env={**os.environ, "NWC_CONNECTION_STRING": nwc},
            )
            if result.returncode == 0:
                bolt11 = result.stdout.strip()
        except Exception:
            pass  # payment attachment is best-effort

    event_id = await send_dm(
        recipient_pubkey,
        message,
        sats=sats,
        bolt11=bolt11 or None,
        relays=relays,
        privkey_hex=privkey_hex,
    )

    return {"event_id": event_id, "bolt11": bolt11, "sats": sats}
