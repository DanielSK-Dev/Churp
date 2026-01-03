"""
churp.py
--------
Import-friendly wrapper around client.PeerClient with BOTH:
  1) listen() queue-based consumption
  2) event-based callbacks (on/once/off)

Singleton usage:
    from churp import Churp

    Churp.on("json", lambda m: print("JSON:", m.sender, m.data))
    Churp.on("chat", lambda m: print("CHAT:", m.sender, m.data))

    Churp.register("Alice")
    Churp.connect("Bob")

    Churp.send({"op": "ping"})
    Churp.send("yo!")

    for msg in Churp.listen():
        print("LISTEN:", msg.kind, msg.sender, msg.data)
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generator, List, Optional, Union

from client import PeerClient

JsonLike = Union[Dict[str, Any], list]
Handler = Callable[["ChurpMessage"], None]


@dataclass
class ChurpMessage:
    kind: str                 # "chat" | "json" | "bytes" | "system"
    sender: str
    data: Any
    ts: float
    raw: Optional[Dict[str, Any]] = None


class Churp:
    _default: Optional["Churp"] = None

    def __init__(
        self,
        *,
        signaling_ip: str = None,
        signaling_port: int = None,
        auto_relay_fallback: bool = True,
    ):
        # Low-level client
        if signaling_ip is None and signaling_port is None:
            self.client = PeerClient(enable_auto_relay_fallback=auto_relay_fallback)
        elif signaling_ip is not None and signaling_port is not None:
            self.client = PeerClient(
                signaling_ip=signaling_ip,
                signaling_port=signaling_port,
                enable_auto_relay_fallback=auto_relay_fallback,
            )
        else:
            raise ValueError("Provide both signaling_ip and signaling_port, or neither.")

        # Queue for listen()
        self._inbox: "queue.Queue[ChurpMessage]" = queue.Queue()

        # Queue for dispatching to event handlers (kept separate so handlers can't block inbox)
        self._dispatch_q: "queue.Queue[ChurpMessage]" = queue.Queue()
        self._dispatch_stop = threading.Event()

        # Handlers map: kind -> list[handler]
        # kind can be: "chat", "json", "bytes", "system", "*"
        self._handlers: Dict[str, List[Handler]] = {
            "chat": [],
            "json": [],
            "bytes": [],
            "system": [],
            "*": [],
        }
        self._handlers_lock = threading.Lock()

        # Start dispatcher thread
        self._dispatcher_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatcher_thread.start()

        # Hook low-level callbacks
        self.client.on_message = self._on_text
        self.client.on_packet = self._on_packet

    # ----------------------------
    # Singleton accessor
    # ----------------------------
    @classmethod
    def default(cls) -> "Churp":
        if cls._default is None:
            cls._default = cls()
        return cls._default

    # ----------------------------
    # Classmethod facade
    # ----------------------------
    @classmethod
    def register(cls, username: str) -> "Churp":
        inst = cls.default()
        inst.register_(username)
        return inst

    @classmethod
    def unregister(cls) -> None:
        cls.default().unregister_()

    @classmethod
    def connect(cls, peer_username: str) -> None:
        cls.default().connect_(peer_username)

    @classmethod
    def disconnect(cls) -> None:
        cls.default().disconnect_()

    @classmethod
    def send(cls, packet: Union[JsonLike, str, bytes], *, to: Optional[str] = None) -> int:
        return cls.default().send_(packet, to=to)

    @classmethod
    def listen(cls, timeout: Optional[float] = None) -> Generator[ChurpMessage, None, None]:
        yield from cls.default().listen_(timeout=timeout)

    @classmethod
    def listen_once(cls, timeout: Optional[float] = None) -> Optional[ChurpMessage]:
        return cls.default().listen_once_(timeout=timeout)

    @classmethod
    def set_relay(cls, enabled: bool) -> None:
        cls.default().set_relay_(enabled)

    @classmethod
    def status(cls) -> Dict[str, Any]:
        return cls.default().status_()

    # ---- events (classmethod facade) ----
    @classmethod
    def on(cls, kind: str, handler: Handler) -> None:
        cls.default().on_(kind, handler)

    @classmethod
    def once(cls, kind: str, handler: Handler) -> None:
        cls.default().once_(kind, handler)

    @classmethod
    def off(cls, kind: str, handler: Handler) -> None:
        cls.default().off_(kind, handler)

    @classmethod
    def clear_handlers(cls, kind: Optional[str] = None) -> None:
        cls.default().clear_handlers_(kind)

    # ----------------------------
    # Instance API
    # ----------------------------
    def register_(self, username: str) -> None:
        if self.client.registered:
            if username != self.client.username:
                raise RuntimeError(
                    f"Already registered as '{self.client.username}'. "
                    f"Call unregister() first if you want to register as '{username}'."
                )
            return
        self.client.register(username)
        self._push_system(f"registered as '{username}'")

    def unregister_(self) -> None:
        # Stop sockets
        if self.client.registered:
            me = self.client.username
            self.client.unregister()
            self._push_system(f"unregistered '{me}'")

    def connect_(self, peer_username: str) -> None:
        if not self.client.registered:
            raise RuntimeError("Not registered. Call Churp.register(username) first.")
        self.client.connect_peer(peer_username)
        self._push_system(f"connecting to peer '{peer_username}' (waiting for signaling...)")

    def wait_for_peer(self, timeout: float = 10.0) -> bool:
        ok = self.client.wait_for_peer(timeout=timeout)
        if ok:
            self._push_system(
                f"peer ready: {self.client.peer_username} @ {self.client.peer_ip}:{self.client.peer_port}"
            )
        return ok

    def disconnect_(self) -> None:
        if self.client.peer_username:
            peer = self.client.peer_username
            self.client.disconnect_peer()
            self._push_system(f"disconnected from peer '{peer}'")

    def send_(self, packet: Union[JsonLike, str, bytes], *, to: Optional[str] = None) -> int:
        if not self.client.registered:
            raise RuntimeError("Not registered. Call Churp.register(username) first.")

        if to and to != self.client.peer_username:
            self.connect_(to)

        if not self.client.peer_username:
            if not self.wait_for_peer(timeout=10.0):
                raise TimeoutError("Timed out waiting for peer info from signaling server.")

        if isinstance(packet, (dict, list)):
            return self.client.send_json(packet)

        if isinstance(packet, str):
            return self.client.send_chat(packet)

        if isinstance(packet, (bytes, bytearray)):
            return self.client.send_bytes(bytes(packet), kind="bytes")

        raise TypeError("packet must be dict/list (JSON), str (chat), or bytes.")

    def set_relay_(self, enabled: bool) -> None:
        self.client.use_relay = bool(enabled)
        self._push_system(f"relay is now {'ON' if self.client.use_relay else 'OFF'}")

    def status_(self) -> Dict[str, Any]:
        return {
            "registered": self.client.registered,
            "username": self.client.username,
            "peer": self.client.peer_username,
            "peer_addr": (self.client.peer_ip, self.client.peer_port),
            "relay": self.client.use_relay,
        }

    # ----------------------------
    # Listening (queue-based)
    # ----------------------------
    def listen_(self, timeout: Optional[float] = None) -> Generator[ChurpMessage, None, None]:
        while True:
            msg = self.listen_once_(timeout=timeout)
            if msg is None:
                continue
            yield msg

    def listen_once_(self, timeout: Optional[float] = None) -> Optional[ChurpMessage]:
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    # ----------------------------
    # Event system
    # ----------------------------
    def on_(self, kind: str, handler: Handler) -> None:
        kind = self._normalize_kind(kind)
        with self._handlers_lock:
            self._handlers.setdefault(kind, [])
            if handler not in self._handlers[kind]:
                self._handlers[kind].append(handler)

    def off_(self, kind: str, handler: Handler) -> None:
        kind = self._normalize_kind(kind)
        with self._handlers_lock:
            if kind in self._handlers and handler in self._handlers[kind]:
                self._handlers[kind].remove(handler)

    def once_(self, kind: str, handler: Handler) -> None:
        kind = self._normalize_kind(kind)

        def _wrapper(msg: ChurpMessage) -> None:
            try:
                handler(msg)
            finally:
                self.off_(kind, _wrapper)

        self.on_(kind, _wrapper)

    def clear_handlers_(self, kind: Optional[str] = None) -> None:
        with self._handlers_lock:
            if kind is None:
                for k in list(self._handlers.keys()):
                    self._handlers[k].clear()
            else:
                kind = self._normalize_kind(kind)
                self._handlers.setdefault(kind, [])
                self._handlers[kind].clear()

    def _dispatch_loop(self) -> None:
        while not self._dispatch_stop.is_set():
            try:
                msg = self._dispatch_q.get(timeout=0.25)
            except queue.Empty:
                continue

            # Snapshot handlers to avoid holding lock while executing user code
            with self._handlers_lock:
                specific = list(self._handlers.get(msg.kind, []))
                wildcard = list(self._handlers.get("*", []))

            # Run handlers safely
            for h in (specific + wildcard):
                try:
                    h(msg)
                except Exception as e:
                    # Don't crash dispatcher because of handler errors
                    print(f"[Churp] handler error ({msg.kind}): {e}")

    def _normalize_kind(self, kind: str) -> str:
        k = (kind or "").strip().lower()
        if k in ("*", "all"):
            return "*"
        if k in ("chat", "json", "bytes", "system"):
            return k
        raise ValueError("kind must be one of: chat, json, bytes, system, *")

    # ----------------------------
    # Internal: enqueue + callbacks
    # ----------------------------
    def _emit(self, msg: ChurpMessage) -> None:
        # Always allow listen() users to consume
        self._inbox.put(msg)
        # Always dispatch events (non-blocking)
        self._dispatch_q.put(msg)

    def _push_system(self, text: str) -> None:
        self._emit(ChurpMessage(kind="system", sender="system", data=text, ts=time.time()))

    def _on_text(self, sender: str, text: str) -> None:
        self._emit(ChurpMessage(kind="chat", sender=sender, data=text, ts=time.time()))

    def _on_packet(self, sender: str, packet: Any) -> None:
        kind = "json" if isinstance(packet, (dict, list)) else "bytes"
        self._emit(ChurpMessage(kind=kind, sender=sender, data=packet, ts=time.time()))
