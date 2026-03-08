"""
nostr-agent-mcp — Nostr identity and encrypted messaging for autonomous AI agents.

Install as an MCP server so any AI model gets a persistent cryptographic
identity and encrypted peer-to-peer communication with other agents.

Claude Desktop config:
    {
      "mcpServers": {
        "nostr-agent": {
          "command": "uvx",
          "args": ["nostr-agent-mcp"],
          "env": { "NOSTR_NSEC": "nsec1..." }
        }
      }
    }
"""

from .crypto import generate_privkey, load_privkey, nip44_decrypt, nip44_encrypt, pubkey_from_privkey
from .identity import build_agent_manifest, discover_agents, fetch_agent_profile, publish_manifest
from .messaging import receive_dms, send_dm, send_dm_with_payment

__all__ = [
    "generate_privkey", "load_privkey", "pubkey_from_privkey",
    "nip44_encrypt", "nip44_decrypt",
    "build_agent_manifest", "publish_manifest", "fetch_agent_profile", "discover_agents",
    "send_dm", "receive_dms", "send_dm_with_payment",
]
__version__ = "0.1.0"
