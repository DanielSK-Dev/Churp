CHURP SETUP GUIDE (Windows / PyCharm / CLI)
==========================================

This guide assumes your project folder contains:
  - client.py
  - churp.py
  - (optional) gui.py
  - (optional) tests/

NOTE ABOUT THE SIGNALING SERVER
------------------------------
CHURP uses an external signaling server to find peers and exchange connection info.
Make sure your signaling server is running and reachable.

The default signaling server is configured inside client.py:
  SIGNALING_SERVER_IP
  SIGNALING_SERVER_PORT

If those values are wrong or the server is offline, peer connections will fail.

----------------------------------------------------------------------
1) Create / Activate a Virtual Environment
----------------------------------------------------------------------

Option A: PyCharm
- Open the project in PyCharm
- Go to: Settings -> Project -> Python Interpreter
- Create/select a venv at: .venv

Option B: Command Line (Windows)
- Open CMD or PowerShell in the project folder and run:

  python -m venv .venv
  .venv\Scripts\activate

You should see the venv activated in your prompt.

----------------------------------------------------------------------
2) Install Dependencies
----------------------------------------------------------------------

Install required dependency:

  pip install cryptography

(If you already installed it, pip will say it's satisfied.)

----------------------------------------------------------------------
3) Confirm Signaling Server Configuration
----------------------------------------------------------------------

Open client.py and verify:

  SIGNALING_SERVER_IP = "198.211.117.27"
  SIGNALING_SERVER_PORT = 5555

If you moved the signaling server, change these values.

----------------------------------------------------------------------
4) Windows Firewall (Recommended Check)
----------------------------------------------------------------------

If messages don't arrive, Windows Firewall may be blocking python.exe.
You can:
- Allow Python through Firewall prompts if they appear
- Or manually allow inbound/outbound rules for python.exe in Windows Defender Firewall

This matters for UDP traffic and sometimes TCP signaling.

----------------------------------------------------------------------
5) Basic Two-Client Test (Same PC / Same NAT)
----------------------------------------------------------------------

IMPORTANT:
If you run BOTH clients on the same PC or same router/network,
force RELAY MODE for the most reliable behavior:

  Churp.set_relay(True)

Why:
Many routers do not support UDP hairpin properly, which breaks direct P2P on same NAT.

----------------------------------------------------------------------
6) Create Two Simple Runner Scripts
----------------------------------------------------------------------

Create a file: alice_run.py
---------------------------
from churp import Churp

Churp.on("system", lambda m: print("[SYS]", m.data))
Churp.on("chat",   lambda m: print("[CHAT]", m.sender + ":", m.data))
Churp.on("json",   lambda m: print("[JSON]", m.sender + ":", m.data))

Churp.register("Alice")
Churp.connect("Bob")

# If testing on same PC/router, force relay:
Churp.set_relay(True)

Churp.send("Hello Bob!")
Churp.send({"op": "ping", "n": 1})

# Keep process alive and receiving
for _ in Churp.listen():
    pass


Create a file: bob_run.py
-------------------------
from churp import Churp

Churp.on("system", lambda m: print("[SYS]", m.data))
Churp.on("chat",   lambda m: print("[CHAT]", m.sender + ":", m.data))
Churp.on("json",   lambda m: print("[JSON]", m.sender + ":", m.data))

Churp.register("Bob")
Churp.connect("Alice")

# If testing on same PC/router, force relay:
Churp.set_relay(True)

Churp.send("Hey Alice!")
Churp.send({"op": "pong"})

# Keep process alive and receiving
for _ in Churp.listen():
    pass

----------------------------------------------------------------------
7) Run Both Clients
----------------------------------------------------------------------

Open two terminals (or two PyCharm run configurations).

Terminal 1:
  python alice_run.py

Terminal 2:
  python bob_run.py

If both are on the same PC/router:
- Make sure BOTH scripts call:
    Churp.set_relay(True)

----------------------------------------------------------------------
8) Common Errors
----------------------------------------------------------------------

Error: target_not_online
Cause:
- The peer username wasn't registered yet when you tried to connect.

Fix:
- Start Alice first (register)
- Start Bob second (register)
- They can then connect.

Connected but no messages:
Fix:
- Force relay on BOTH: Churp.set_relay(True)
- Check firewall rules for python.exe
- Confirm signaling server reachable

Message: "No UDP packets received... enabling relay"
Meaning:
- Direct UDP isn't working (common on same NAT).
- Relay mode is expected and should work.

----------------------------------------------------------------------
DONE
----------------------------------------------------------------------

You should now be able to:
- Churp.register("Name")
- Churp.connect("OtherName")
- Churp.send("text") or Churp.send({"json": "packet"})
- Receive via events or Churp.listen()

If you want, the next step is packaging so you can:
  pip install -e .
and import CHURP like a normal module anywhere.
