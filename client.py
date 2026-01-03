import socket
import threading
import time
import json
import base64
import random
import os
from typing import Any, Callable, Dict, Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --------- CONFIG (defaults; can be overridden via PeerClient(...)) ---------
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
# --------------------------------------------------------------------------


JsonLike = Union[Dict[str, Any], list]
PacketArg = Union[JsonLike, str, bytes]


class PeerClient:
    """
    Low-level P2P client that:
      - Registers with a TCP signaling server
      - Uses UDP hole-punching to reach a peer
      - Encrypts payloads using hybrid RSA(AES-key) + AES-CBC (legacy from original project)
      - Optionally falls back to relaying payloads via the signaling server

    This class is still compatible with your GUI integration:
      - self.on_message(sender: str, text: str) is called for "chat" messages
    New for library use:
      - self.on_packet(sender: str, packet: Any) is called for "data" messages (decoded JSON or bytes)
    """

    def __init__(
        self,
        signaling_ip: str = SIGNALING_SERVER_IP,
        signaling_port: int = SIGNALING_SERVER_PORT,
        *,
        enable_auto_relay_fallback: bool = True,
    ):
        # Identity / sockets
        self.username: Optional[str] = None
        self.sock: Optional[socket.socket] = None
        self.tcp: Optional[socket.socket] = None
        self.tcp_lock = threading.Lock()

        # Signaling target
        self.signaling_ip = signaling_ip
        self.signaling_port = int(signaling_port)

        # Current peer (single-peer model)
        self.peer_ip: Optional[str] = None
        self.peer_port: Optional[int] = None
        self.peer_username: Optional[str] = None

        # Crypto
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.key_exchange_complete = threading.Event()

        # State
        self.registered = False
        self.use_relay = False
        self.enable_auto_relay_fallback = enable_auto_relay_fallback
        self.stop_evt = threading.Event()
        self.local_udp_port: Optional[int] = None
        self.peer_ready_evt = threading.Event()

        # Message IDs (simple de-dupe)
        self.my_parity: Optional[int] = None
        self._send_counter = 0
        self._last_recv_id = -1

        # Tracks if we got any UDP packets from the peer
        self._udp_seen_event = threading.Event()

        # Callbacks (optional)
        self.on_message: Optional[Callable[[str, str], None]] = None  # for "chat"
        self.on_packet: Optional[Callable[[str, Any], None]] = None   # for "data"

    # ---------- RSA KEYPAIR ----------
    def generate_keys(self) -> None:
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def set_peer_public_key(self, pem_bytes: bytes) -> None:
        self.peer_public_key = serialization.load_pem_public_key(
            pem_bytes, backend=default_backend()
        )

    def encrypt_message(self, message: bytes) -> Dict[str, str]:
        """
        Encrypts 'message' bytes into {key, iv, data} using:
          - random AES-256 key encrypted with peer RSA public key (OAEP SHA256)
          - AES-CBC for data (with PKCS#7-ish padding)
        """
        if not self.peer_public_key:
            raise RuntimeError("Peer public key not set.")

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

    def decrypt_message(self, enc_obj: Dict[str, str]) -> bytes:
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
    def tcp_send_json(self, obj: Dict[str, Any]) -> None:
        if not self.tcp:
            return
        data = (json.dumps(obj) + "\n").encode()
        with self.tcp_lock:
            try:
                self.tcp.sendall(data)
            except Exception as e:
                print("[SIGNAL] send error:", e)

    def signaling_reader(self) -> None:
        buf = b""
        if not self.tcp:
            return

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

    def handle_signal(self, msg: Dict[str, Any]) -> None:
        act = msg.get("action")

        if act == "registered":
            return

        if act == "error":
            print("[SIGNAL][error]", msg.get("error"))
            return

        if act == "peer":
            self.peer_username = msg.get("peer_username")
            self.peer_ip = msg.get("peer_ip")
            self.peer_port = int(msg.get("peer_port"))
            self.my_parity = 0 if (self.username or "") < (self.peer_username or "") else 1
            self._send_counter = 0
            self._last_recv_id = -1
            self._udp_seen_event.clear()
            self.peer_ready_evt.set()

            peer_pubkey_b64 = msg.get("peer_pubkey")
            if peer_pubkey_b64:
                try:
                    key_bytes = base64.b64decode(peer_pubkey_b64)
                    self.set_peer_public_key(key_bytes)
                    self.key_exchange_complete.set()
                except Exception as e:
                    print(f"[CRYPTO] Failed to load peer key: {e}")

            print(f"[SIGNAL] peer: {self.peer_username} @ {self.peer_ip}:{self.peer_port} "
                  f"(my_parity={'even' if self.my_parity==0 else 'odd'})")

            self.start_hole_punch()

            if self.enable_auto_relay_fallback:
                threading.Thread(target=self._relay_fallback_watcher, daemon=True).start()
            return

        print("[SIGNAL] unknown msg:", msg)

    # ---------- REGISTER / UNREGISTER ----------
    def register(self, username: str) -> None:
        if self.registered:
            print("[INFO] Already registered.")
            return

        self.username = username
        self.stop_evt.clear()
        self.peer_ready_evt.clear()
        self.key_exchange_complete.clear()
        self._udp_seen_event.clear()
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

    def unregister(self) -> None:
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
        self.disconnect_peer()

        print("[INFO] Unregistered and cleaned up.")

    # ---------- PEER MANAGEMENT ----------
    def connect_peer(self, target_username: str) -> None:
        if not self.registered:
            raise RuntimeError("Not registered. Call register(username) first.")
        self.send_udp_probe()
        self.peer_ready_evt.clear()
        self.key_exchange_complete.clear()
        self.tcp_send_json({"action": "connect", "target": target_username})

    def disconnect_peer(self) -> None:
        self.peer_username = None
        self.peer_ip = None
        self.peer_port = None
        self.peer_public_key = None
        self.peer_ready_evt.clear()
        self.key_exchange_complete.clear()
        self.my_parity = None
        self._send_counter = 0
        self._last_recv_id = -1
        self.use_relay = False
        self._udp_seen_event.clear()

    def wait_for_peer(self, timeout: Optional[float] = 10.0) -> bool:
        return self.peer_ready_evt.wait(timeout=timeout)

    # ---------- UDP HELPERS ----------
    def send_udp_probe(self) -> None:
        if not self.sock or not self.username:
            return
        try:
            probe = json.dumps({"action": "probe", "username": self.username}).encode()
            self.sock.sendto(probe, (self.signaling_ip, self.signaling_port))
            time.sleep(0.05)
            self.sock.sendto(probe, (self.signaling_ip, self.signaling_port))
        except Exception as e:
            print("[UDP] probe error:", e)

    def start_hole_punch(self) -> None:
        if not (self.sock and self.peer_ip and self.peer_port and self.username):
            return

        def punch():
            for i in range(PUNCH_COUNT):
                pkt = json.dumps({"type": "hello", "from": self.username, "seq": i}).encode()
                try:
                    self.sock.sendto(pkt, (self.peer_ip, self.peer_port))
                except Exception as e:
                    print("[UDP] punch error:", e)
                time.sleep(PUNCH_INTERVAL + random.uniform(0, 0.01))
            self.start_keepalive()

        threading.Thread(target=punch, daemon=True).start()

    def start_keepalive(self) -> None:
        if not (self.sock and self.peer_ip and self.peer_port and self.username):
            return

        def ka():
            while not self.stop_evt.is_set() and self.peer_ip and self.peer_port and self.sock:
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
    def _relay_fallback_watcher(self) -> None:
        if self._udp_seen_event.wait(timeout=RELAY_FALLBACK_TIMEOUT):
            return
        self.use_relay = True
        print("[WARN] No UDP packets received from peer; enabling relay mode automatically.")

    # ---------- SEND HELPERS ----------
    def _send_with_redundancy(self, payload_bytes: bytes, addr) -> None:
        if not self.sock:
            return
        for n in range(REDUNDANT_SENDS):
            try:
                self.sock.sendto(payload_bytes, addr)
            except Exception as e:
                if n == 0:
                    print("[UDP] send error:", e)
            time.sleep(REDUNDANT_SPACING + random.uniform(0, REDUNDANT_JITTER))

    def _next_msg_id(self) -> int:
        if self.my_parity is None:
            self.my_parity = 0
        msg_id = 2 * self._send_counter + self.my_parity
        self._send_counter += 1
        return msg_id

    def _require_peer_ready(self) -> None:
        if not self.registered:
            raise RuntimeError("Not registered. Call register(username) first.")
        if not (self.peer_ip and self.peer_port and self.peer_username):
            raise RuntimeError("No peer yet. Call connect_peer(target_username) first.")
        if not self.key_exchange_complete.is_set():
            if not self.key_exchange_complete.wait(timeout=5):
                raise RuntimeError("Peer public key not received.")

    def send_chat(self, text: str) -> int:
        self._require_peer_ready()

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
        self._send_envelope(raw, to_peer=True)
        return msg_id

    def send_json(self, obj: JsonLike) -> int:
        payload = json.dumps(obj).encode("utf-8")
        return self.send_bytes(payload, kind="json")

    def send_bytes(self, payload: bytes, *, kind: str = "bytes") -> int:
        self._require_peer_ready()

        msg_id = self._next_msg_id()
        encrypted = self.encrypt_message(payload)
        packet = {
            "type": "data",
            "kind": kind,
            "id": msg_id,
            "from": self.username,
            "to": self.peer_username,
            "ts": time.time(),
            "encrypted": encrypted
        }
        raw = json.dumps(packet).encode()
        self._send_envelope(raw, to_peer=True)
        return msg_id

    def _send_envelope(self, raw_packet: bytes, *, to_peer: bool) -> None:
        if not self.sock:
            return

        if self.use_relay:
            env = {
                "action": "relay",
                "to": self.peer_username,
                "payload": base64.b64encode(raw_packet).decode()
            }
            env_raw = json.dumps(env).encode()
            threading.Thread(
                target=self._send_with_redundancy,
                args=(env_raw, (self.signaling_ip, self.signaling_port)),
                daemon=True
            ).start()
            return

        if to_peer and self.peer_ip and self.peer_port:
            threading.Thread(
                target=self._send_with_redundancy,
                args=(raw_packet, (self.peer_ip, self.peer_port)),
                daemon=True
            ).start()

    # ---------- RECEIVE LOOP ----------
    def udp_receiver(self) -> None:
        if not self.sock:
            return
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

            if mtype in ("hello", "chat", "data") and self.peer_username and msg.get("from") == self.peer_username:
                self._udp_seen_event.set()
                if (self.peer_ip, self.peer_port) != addr:
                    self.peer_ip, self.peer_port = addr

            if mtype == "hello":
                reply = {"type": "hello", "from": self.username, "seq": msg.get("seq", 0)}
                try:
                    self.sock.sendto(json.dumps(reply).encode(), addr)
                except Exception:
                    pass
                continue

            if mtype not in ("chat", "data"):
                continue

            mid = msg.get("id")
            if isinstance(mid, int) and mid <= self._last_recv_id:
                continue
            if isinstance(mid, int):
                self._last_recv_id = mid

            enc = msg.get("encrypted")
            if not enc:
                continue

            try:
                decrypted = self.decrypt_message(enc)
            except Exception as e:
                print(f"[ERROR] decrypt failed: {e}")
                continue

            sender = msg.get("from") or "unknown"

            if mtype == "chat":
                text = decrypted.decode(errors="replace")
                if self.on_message:
                    self.on_message(sender, text)
                else:
                    print(f"\n[{sender} -> {msg.get('to')}] {text}  (id={mid})")
                continue

            kind = msg.get("kind", "bytes")
            if kind == "json":
                try:
                    obj = json.loads(decrypted.decode("utf-8"))
                except Exception:
                    obj = {"_decode_error": True, "raw": decrypted.decode(errors="replace")}
                if self.on_packet:
                    self.on_packet(sender, obj)
                elif self.on_message:
                    self.on_message(sender, json.dumps(obj, indent=2))
                else:
                    print(f"\n[{sender} -> {msg.get('to')}] {obj}  (id={mid})")
            else:
                if self.on_packet:
                    self.on_packet(sender, decrypted)
                elif self.on_message:
                    self.on_message(sender, decrypted.decode(errors="replace"))
                else:
                    print(f"\n[{sender} -> {msg.get('to')}] <{len(decrypted)} bytes>  (id={mid})")
