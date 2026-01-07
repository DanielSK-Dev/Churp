# CHURP (Cryptographic Headless User Routing Protocol) — Encrypted P2P Chat + JSON Packet Transport (with Relay Fallback)

CHURP is a lightweight Python networking layer that lets two users:
- **register** with a signaling server
- **connect** to another user by username
- send **encrypted** messages and **JSON packets**
- receive messages via **listen()** or **event callbacks**
- optionally **relay** traffic through the signaling server (important for same PC / same NAT / same LAN hairpin issues)

This repo is designed so you can import and use CHURP without any GUI.

---

## Repo Contents

- `client.py`  
  Low-level networking + crypto. Contains `PeerClient`.
- `churp.py`  
  High-level, import-friendly wrapper. Contains `Churp`.
- `gui.py` (optional / legacy)  
  Old GUI (not required).
- `tests/`  
  Local scripts (`test.py`, `test2.py`, etc.). Usually ignored by Git.

---

## Requirements

- Python 3.10+ recommended (3.12 works)
- Python dependency:
  - `cryptography`

Install dependency:
```bash
pip install cryptography

