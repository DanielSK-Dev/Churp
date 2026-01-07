CHURP EXAMPLE — Simple P2P Messaging
=================================================

This example shows a slightly more complete two-user P2P messaging flow with:
- event handlers
- a tiny command loop
- optional relay forcing (for same PC/NAT)
- sending both chat text and JSON packets

-------------------------------------------------
FILES REQUIRED IN SAME FOLDER
-------------------------------------------------
- churp.py
- client.py

-------------------------------------------------
HOW TO USE THIS EXAMPLE
-------------------------------------------------
1) Make TWO copies of this file:
   - alice_example.py
   - bob_example.py

2) In alice_example.py set:
     MY_NAME = "Alice"
     PEER_NAME = "Bob"

   In bob_example.py set:
     MY_NAME = "Bob"
     PEER_NAME = "Alice"

3) Run both in two terminals:
     python alice_example.py
     python bob_example.py

4) If testing on the same PC/router, type:
     /relay on
   in BOTH terminals (or set FORCE_RELAY=True below).

-------------------------------------------------
PASTE THIS CODE INTO alice_example.py AND bob_example.py
-------------------------------------------------

import json
import time
from churp import Churp

# =========================
# Config (edit per user)
# =========================
MY_NAME = "Bob"       # change to "Alice" in alice_example.py
PEER_NAME = "Alice"   # change to "Bob" in alice_example.py

AUTO_CONNECT = True
FORCE_RELAY = False   # set True if same PC/router (recommended for local testing)


# =========================
# Event handlers
# =========================
def on_system(m):
    print(f"[SYS] {m.data}")

def on_chat(m):
    print(f"[CHAT] {m.sender}: {m.data}")

def on_json(m):
    pretty = json.dumps(m.data, indent=2)
    print(f"[JSON] {m.sender}:\n{pretty}")

def on_bytes(m):
    data = m.data
    if isinstance(data, (bytes, bytearray)):
        print(f"[BYTES] {m.sender}: {len(data)} bytes")
    else:
        print(f"[BYTES] {m.sender}: {data!r}")


def print_help():
    print("")
    print("Commands:")
    print("  /help                 show this help")
    print("  /connect <peer>        connect to peer username")
    print("  /json <json>           send a JSON packet")
    print("  /relay on|off          force relay on/off (use on same NAT/PC)")
    print("  /status                print status")
    print("  /quit                  exit")
    print("")
    print("Any other text is sent as chat.")
    print("")


def main():
    # Register handlers
    Churp.on("system", on_system)
    Churp.on("chat", on_chat)
    Churp.on("json", on_json)
    Churp.on("bytes", on_bytes)

    # Register user
    Churp.register(MY_NAME)

    # Auto-connect
    if AUTO_CONNECT and PEER_NAME:
        Churp.connect(PEER_NAME)

    # Optional relay force
    if FORCE_RELAY:
        Churp.set_relay(True)

    print_help()

    # Send a hello packet
    try:
        Churp.send({"op": "hello", "from": MY_NAME, "ts": time.time()})
    except Exception as e:
        print("[WARN] initial hello send failed:", e)

    # Simple input loop
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue

        if line == "/help":
            print_help()
            continue

        if line.startswith("/connect "):
            peer = line[len("/connect "):].strip()
            if peer:
                Churp.connect(peer)
            else:
                print("Usage: /connect <peer>")
            continue

        if line.startswith("/json "):
            raw = line[len("/json "):].strip()
            try:
                obj = json.loads(raw)
            except Exception as e:
                print("[ERR] Invalid JSON:", e)
                continue
            try:
                Churp.send(obj)
            except Exception as e:
                print("[ERR] send failed:", e)
            continue

        if line.startswith("/relay "):
            mode = line[len("/relay "):].strip().lower()
            if mode not in ("on", "off"):
                print("Usage: /relay on|off")
                continue
            Churp.set_relay(mode == "on")
            continue

        if line == "/status":
            print(Churp.status())
            continue

        if line == "/quit":
            break

        # Default: send chat
        try:
            Churp.send(line)
        except Exception as e:
            print("[ERR] send failed:", e)

    # Cleanup
    try:
        Churp.disconnect()
    except Exception:
        pass
    try:
        Churp.unregister()
    except Exception:
        pass

    print("Bye!")


if __name__ == "__main__":
    main()

-------------------------------------------------
NOTES
-------------------------------------------------
- If you're running both clients on the same router or same PC, relay mode is usually required:
    /relay on
  in both terminals.

- You can send JSON packets like:
    /json {"op":"ping","n":1}

- You can send normal chat by typing text and hitting Enter.
