import socket
import threading
import time
import json
import sys
import base64
import random
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --------- CONFIG ---------
SIGNALING_SERVER_IP = "198.211.117.27"
SIGNALING_SERVER_PORT = 5555

PUNCH_COUNT = 12
PUNCH_INTERVAL = 0.1
KEEPALIVE_INTERVAL = 20.0
RELAY_FALLBACK_TIMEOUT = 5.0  # seconds to wait for UDP before switching to relay

# UDP reliability (duplicate sends)
REDUNDANT_SENDS = 5
REDUNDANT_SPACING = 0.035
REDUNDANT_JITTER = 0.010
# --------------------------


class PeerClient:
    def __init__(self):
        self.username = None
        self.sock = None
        self.tcp = None
        self.tcp_lock = threading.Lock()
        self.signaling_ip = SIGNALING_SERVER_IP
        self.signaling_port = SIGNALING_SERVER_PORT

        self.peer_ip = None
        self.peer_port = None
        self.peer_username = None

        # Crypto
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.key_exchange_complete = threading.Event()

        # State
        self.registered = False
        self.use_relay = False
        self.stop_evt = threading.Event()
        self.local_udp_port = None

        # Message IDs
        self.my_parity = None
        self._send_counter = 0
        self._last_recv_id = -1

        # Tracks if we got any UDP packets from the peer
        self._udp_seen_event = threading.Event()

    # ---------- RSA KEYPAIR ----------
    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def set_peer_public_key(self, pem_bytes):
        self.peer_public_key = serialization.load_pem_public_key(
            pem_bytes, backend=default_backend()
        )

    def encrypt_message(self, message: bytes):
        aes_key = os.urandom(32)
        encrypted_key = self.peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pad_len = 16 - (len(message) % 16)
        padded = message + bytes([pad_len]) * pad_len

        enc_data = encryptor.update(padded) + encryptor.finalize()
        return {
            "key": base64.b64encode(encrypted_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(enc_data).decode(),
        }

    def decrypt_message(self, enc_obj):
        encrypted_key = base64.b64decode(enc_obj["key"])
        iv = base64.b64decode(enc_obj["iv"])
        enc_data = base64.b64decode(enc_obj["data"])

        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(enc_data) + decryptor.finalize()
        pad_len = padded[-1]
        return padded[:-pad_len]

    # ---------- TCP SIGNALING ----------
    def tcp_send_json(self, obj):
        data = (json.dumps(obj) + "\n").encode()
        with self.tcp_lock:
            try:
                self.tcp.sendall(data)
            except Exception as e:
                print("[SIGNAL] send error:", e)

    def signaling_reader(self):
        buf = b""
        self.tcp.settimeout(1.0)
        while not self.stop_evt.is_set() and self.tcp:
            try:
                chunk = self.tcp.recv(4096)
                if not chunk:
                    print("[SIGNAL] disconnected from server")
                    self.unregister()
                    break
                buf += chunk
            except socket.timeout:
                continue
            except Exception as e:
                print("[SIGNAL] error:", e)
                self.unregister()
                break

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line.decode())
                except json.JSONDecodeError:
                    continue
                self.handle_signal(msg)

    def handle_signal(self, msg):
        act = msg.get("action")
        if act == "registered":
            print(f"[SIGNAL] registered as {msg.get('username')}")
        elif act == "error":
            print("[SIGNAL][error]", msg.get("error"))
        elif act == "peer":
            self.peer_username = msg.get("peer_username")
            self.peer_ip = msg.get("peer_ip")
            self.peer_port = int(msg.get("peer_port"))
            self.my_parity = 0 if self.username < self.peer_username else 1
            self._send_counter = 0
            self._last_recv_id = -1
            self._udp_seen_event.clear()

            # Load peer’s public key from signaling
            peer_pubkey_b64 = msg.get("peer_pubkey")
            if peer_pubkey_b64:
                try:
                    key_bytes = base64.b64decode(peer_pubkey_b64)
                    self.set_peer_public_key(key_bytes)
                    self.key_exchange_complete.set()
                    print("[CRYPTO] Loaded peer’s public key from signaling server")
                except Exception as e:
                    print(f"[CRYPTO] Failed to load peer key: {e}")

            print(f"[SIGNAL] peer: {self.peer_username} @ {self.peer_ip}:{self.peer_port} "
                  f"(my_parity={'even' if self.my_parity==0 else 'odd'})")
            self.start_hole_punch()
            threading.Thread(target=self._relay_fallback_watcher, daemon=True).start()
        else:
            print("[SIGNAL] unknown msg:", msg)

    # ---------- REGISTER / UNREGISTER ----------
    def register(self, username):
        if self.registered:
            print("[INFO] Already registered.")
            return
        self.username = username
        self.stop_evt.clear()
        self.generate_keys()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))
        self.sock.settimeout(0.5)
        self.local_udp_port = self.sock.getsockname()[1]

        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.connect((self.signaling_ip, self.signaling_port))

        pubkey_b64 = base64.b64encode(self.get_public_key_bytes()).decode()
        self.tcp_send_json({
            "action": "register",
            "username": self.username,
            "udp_port": self.local_udp_port,
            "public_key": pubkey_b64
        })

        threading.Thread(target=self.signaling_reader, daemon=True).start()
        threading.Thread(target=self.udp_receiver, daemon=True).start()
        self.send_udp_probe()
        self.registered = True
        print(f"[INFO] Registered as '{self.username}', UDP port {self.local_udp_port}")

    def unregister(self):
        self.registered = False
        self.stop_evt.set()
        try:
            if self.tcp:
                self.tcp.close()
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.tcp = None
        self.sock = None
        self.username = None
        self.peer_username = None
        self.peer_ip = None
        self.peer_port = None
        print("[INFO] Unregistered and cleaned up.")

    # ---------- UDP HELPERS ----------
    def send_udp_probe(self):
        try:
            probe = json.dumps({"action": "probe", "username": self.username}).encode()
            self.sock.sendto(probe, (self.signaling_ip, self.signaling_port))
            time.sleep(0.05)
            self.sock.sendto(probe, (self.signaling_ip, self.signaling_port))
            print("[UDP] sent probe to signaling for NAT discovery")
        except Exception as e:
            print("[UDP] probe error:", e)

    def start_hole_punch(self):
        if not (self.peer_ip and self.peer_port):
            return

        def punch():
            for i in range(PUNCH_COUNT):
                pkt = json.dumps({"type": "hello", "from": self.username, "seq": i}).encode()
                try:
                    self.sock.sendto(pkt, (self.peer_ip, self.peer_port))
                except Exception as e:
                    print("[UDP] punch error:", e)
                time.sleep(PUNCH_INTERVAL + random.uniform(0, 0.01))
            print("[UDP] hole punch packets sent.")
            self.start_keepalive()

        threading.Thread(target=punch, daemon=True).start()

    def start_keepalive(self):
        def ka():
            while not self.stop_evt.is_set() and self.peer_ip and self.peer_port:
                pkt = json.dumps({
                    "type": "hello",
                    "from": self.username,
                    "seq": int(time.time())
                }).encode()
                try:
                    self.sock.sendto(pkt, (self.peer_ip, self.peer_port))
                except Exception:
                    pass
                time.sleep(KEEPALIVE_INTERVAL)
        threading.Thread(target=ka, daemon=True).start()

    # ---------- AUTOMATIC RELAY FALLBACK ----------
    def _relay_fallback_watcher(self):
        """Wait RELAY_FALLBACK_TIMEOUT seconds for any UDP from peer; switch to relay if none."""
        if self._udp_seen_event.wait(timeout=RELAY_FALLBACK_TIMEOUT):
            print("[UDP] Direct P2P path detected. Staying P2P.")
        else:
            self.use_relay = True
            print("[WARN] No UDP packets received from peer; enabling relay mode automatically.")

    # ---------- CHAT ----------
    def _send_with_redundancy(self, payload_bytes, addr):
        for n in range(REDUNDANT_SENDS):
            try:
                self.sock.sendto(payload_bytes, addr)
            except Exception as e:
                if n == 0:
                    print("[UDP] send error:", e)
            time.sleep(REDUNDANT_SPACING + random.uniform(0, REDUNDANT_JITTER))

    def _next_msg_id(self):
        if self.my_parity is None:
            self.my_parity = 0
        msg_id = 2 * self._send_counter + self.my_parity
        self._send_counter += 1
        return msg_id

    def send_chat(self, text):
        if not self.registered:
            print("[ERROR] You must /register first.")
            return
        if not (self.peer_ip and self.peer_port and self.peer_username):
            print("[UDP] No peer yet. Use /connect <username> first.")
            return
        if not self.key_exchange_complete.is_set():
            if not self.key_exchange_complete.wait(timeout=5):
                print("[ERROR] Peer public key not received.")
                return

        msg_id = self._next_msg_id()
        encrypted = self.encrypt_message(text.encode())
        packet = {
            "type": "chat",
            "id": msg_id,
            "from": self.username,
            "to": self.peer_username,
            "ts": time.time(),
            "encrypted": encrypted
        }
        raw = json.dumps(packet).encode()

        if self.use_relay:
            env = {
                "action": "relay",
                "to": self.peer_username,
                "payload": base64.b64encode(raw).decode()
            }
            env_raw = json.dumps(env).encode()
            threading.Thread(
                target=self._send_with_redundancy,
                args=(env_raw, (self.signaling_ip, self.signaling_port)),
                daemon=True
            ).start()
            print(f"[UDP] Relayed chat via server (id={msg_id})")
            return

        threading.Thread(
            target=self._send_with_redundancy,
            args=(raw, (self.peer_ip, self.peer_port)),
            daemon=True
        ).start()
        print(f"[UDP] Sent chat to {self.peer_username} (id={msg_id})")

    def udp_receiver(self):
        print(f"[INFO] UDP receiver listening on port {self.local_udp_port}")
        while not self.stop_evt.is_set() and self.sock:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as e:
                print("[UDP] recv error:", e)
                break

            try:
                msg = json.loads(data.decode(errors="ignore"))
            except json.JSONDecodeError:
                continue

            if isinstance(msg, dict) and msg.get("action") == "probe_ack":
                continue

            mtype = msg.get("type")
            if mtype in ("hello", "chat") and self.peer_username and msg.get("from") == self.peer_username:
                self._udp_seen_event.set()  # mark that we saw a packet
                if (self.peer_ip, self.peer_port) != addr:
                    self.peer_ip, self.peer_port = addr

            if mtype == "chat":
                mid = msg.get("id")
                if isinstance(mid, int) and mid <= self._last_recv_id:
                    continue
                self._last_recv_id = mid
                enc = msg.get("encrypted")
                if enc:
                    try:
                        decrypted = self.decrypt_message(enc).decode()
                        print(f"\n[{msg.get('from')} -> {msg.get('to')}] {decrypted}  (id={mid})")
                    except Exception as e:
                        print(f"[ERROR] decrypt failed: {e}")
            elif mtype == "hello":
                reply = {"type": "hello", "from": self.username, "seq": msg.get("seq", 0)}
                try:
                    self.sock.sendto(json.dumps(reply).encode(), addr)
                except Exception:
                    pass


def main():
    cli = PeerClient()
    print("Commands:\n"
          "  /register <username>  - register with signaling server\n"
          "  /unregister           - disconnect and cleanup\n"
          "  /connect <username>   - connect to a peer\n"
          "  /relay on|off         - manually toggle relay fallback\n"
          "  /probe                - refresh NAT mapping\n"
          "  /quit                 - exit\n"
          "  (anything else sends a chat message)\n")

    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            if line.startswith("/register "):
                uname = line.split(maxsplit=1)[1].strip()
                cli.register(uname)
            elif line == "/unregister":
                cli.unregister()
            elif line.startswith("/connect "):
                if not cli.registered:
                    print("[ERROR] Must /register first.")
                    continue
                target = line.split(maxsplit=1)[1].strip()
                cli.send_udp_probe()
                cli.tcp_send_json({"action": "connect", "target": target})
            elif line.startswith("/relay "):
                arg = line.split(maxsplit=1)[1].strip().lower()
                cli.use_relay = (arg == "on")
                print(f"[INFO] relay is now {'ON' if cli.use_relay else 'OFF'}")
            elif line == "/probe":
                cli.send_udp_probe()
            elif line == "/quit":
                cli.unregister()
                break
            else:
                cli.send_chat(line)
    except (KeyboardInterrupt, EOFError):
        cli.unregister()
        pass


if __name__ == "__main__":
    main()
