# gui.py
import os
import sys
import json
import base64
import threading
import queue
import time
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from client import PeerClient

DATA_DIR = "secure_chat"
os.makedirs(DATA_DIR, exist_ok=True)

BG = "#0f1115"
PANEL = "#151821"
ACCENT = "#3b82f6"
TEXT = "#e5e7eb"
TEXT_DIM = "#9ca3af"


class SecureChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Churp")
        self.geometry("920x620")
        self.configure(bg=BG)
        self.resizable(True, True)

        self.client = None
        self.msg_queue = queue.Queue()
        self.stop_evt = threading.Event()
        self.seen_ids = set()

        # Session info
        self.username = None
        self.password = None
        self.key = None
        self.chat_data = {}
        self.selected_user = None

        self.current_frame = None
        self.show_login_screen()

    # ---------- FRAME SWITCH ----------
    def show_login_screen(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = LoginFrame(self)
        self.current_frame.pack(fill="both", expand=True)

    def show_chat_screen(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = ChatFrame(self)
        self.current_frame.pack(fill="both", expand=True)


# ---------------------------------------------------------
# LOGIN SCREEN
# ---------------------------------------------------------
class LoginFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app, bg=BG)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        tk.Label(self, text="🔐 Churp Secure Login", bg=BG, fg=TEXT, font=("Segoe UI", 20, "bold")).pack(pady=(60, 10))
        tk.Label(self, text="Username:", bg=BG, fg=TEXT_DIM).pack(pady=(10, 0))
        self.username_entry = tk.Entry(self, width=30, font=("Segoe UI", 12))
        self.username_entry.pack(pady=(0, 10))
        tk.Label(self, text="Password:", bg=BG, fg=TEXT_DIM).pack(pady=(10, 0))
        self.password_entry = tk.Entry(self, width=30, font=("Segoe UI", 12), show="*")
        self.password_entry.pack(pady=(0, 20))

        ttk.Button(self, text="Login", command=self._login).pack(pady=5)
        ttk.Button(self, text="Create New Account", command=self._create_account).pack(pady=5)

    def _cfg_path(self, username): return os.path.join(DATA_DIR, f"config_{username}.json")
    def _chat_path(self, username): return os.path.join(DATA_DIR, f"chat_data_{username}.enc")

    def _derive_key(self, password, salt):
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=200000, backend=default_backend()
        ).derive(password.encode())

    def _encrypt_username(self, username, key):
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(username.encode()) + enc.finalize()
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(enc.tag).decode(),
            "data": base64.b64encode(ciphertext).decode()
        }

    def _decrypt_username(self, cfg, key):
        nonce = base64.b64decode(cfg["nonce"])
        tag = base64.b64decode(cfg["tag"])
        data = base64.b64decode(cfg["data"])
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        dec = cipher.decryptor()
        return (dec.update(data) + dec.finalize()).decode()

    def _login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required.")
            return

        cfg_path = self._cfg_path(username)
        if not os.path.exists(cfg_path):
            messagebox.showerror("Error", "Account does not exist.")
            return

        try:
            with open(cfg_path, "r") as f:
                cfg = json.load(f)
            salt = base64.b64decode(cfg["salt"])
            key = self._derive_key(password, salt)
            if self._decrypt_username(cfg, key) != username:
                raise ValueError("Incorrect password")
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {e}")
            return

        self.app.username = username
        self.app.password = password
        self.app.key = key
        self.app.chat_path = self._chat_path(username)
        self.app.config_path = cfg_path
        self.app.show_chat_screen()

    def _create_account(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required.")
            return
        cfg_path = self._cfg_path(username)
        if os.path.exists(cfg_path):
            messagebox.showerror("Error", "Account already exists.")
            return
        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        enc = self._encrypt_username(username, key)
        cfg = {"salt": base64.b64encode(salt).decode(), **enc}
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        messagebox.showinfo("Success", f"Account '{username}' created.")
        self._login()


# ---------------------------------------------------------
# CHAT SCREEN
# ---------------------------------------------------------
class ChatFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app, bg=BG)
        self.app = app
        self.msg_queue = app.msg_queue
        self.stop_evt = app.stop_evt
        self.seen_ids = app.seen_ids
        self.client = PeerClient()
        self.client.on_message = lambda sender, text: self.msg_queue.put((sender, text))

        self.chat_data = {"users": {}, "username": app.username}
        self.selected_user = None
        self._load_encrypted_data()
        self._build_ui()
        self._populate_users_initial()
        threading.Thread(target=self._auto_register, daemon=True).start()
        self.after(100, self._poll_incoming)

    # ---------- ENCRYPTED STORAGE ----------
    def _encrypt_json(self, data: dict) -> bytes:
        plaintext = json.dumps(data).encode()
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.app.key), modes.GCM(nonce), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()
        return json.dumps({
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(enc.tag).decode(),
            "data": base64.b64encode(ciphertext).decode()
        }).encode()

    def _decrypt_json(self, data_bytes: bytes) -> dict:
        try:
            enc = json.loads(data_bytes.decode())
            nonce = base64.b64decode(enc["nonce"])
            tag = base64.b64decode(enc["tag"])
            data = base64.b64decode(enc["data"])
            cipher = Cipher(algorithms.AES(self.app.key), modes.GCM(nonce, tag), backend=default_backend())
            dec = cipher.decryptor()
            return json.loads((dec.update(data) + dec.finalize()).decode())
        except Exception:
            return {"users": {}, "username": self.app.username}

    def _load_encrypted_data(self):
        if os.path.exists(self.app.chat_path):
            try:
                with open(self.app.chat_path, "rb") as f:
                    enc = f.read()
                self.chat_data = self._decrypt_json(enc)
            except Exception:
                self.chat_data = {"users": {}, "username": self.app.username}

    def _save_encrypted_data(self):
        try:
            enc = self._encrypt_json(self.chat_data)
            with open(self.app.chat_path, "wb") as f:
                f.write(enc)
        except Exception as e:
            print("[WARN] Failed to save chat:", e)

    # ---------- UI ----------
    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = tk.Frame(self, bg=PANEL)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_rowconfigure(1, weight=1)
        tk.Label(sidebar, text=f"User: {self.app.username}", fg=TEXT, bg=PANEL, font=("Segoe UI", 12, "bold")).pack(pady=(10,4))
        tk.Label(sidebar, text="Contacts", fg=TEXT_DIM, bg=PANEL).pack()
        self.user_listbox = tk.Listbox(sidebar, bg=BG, fg=TEXT, selectbackground=ACCENT, selectforeground="white")
        self.user_listbox.pack(fill="both", expand=True, padx=10, pady=(0,10))
        self.user_listbox.bind("<<ListboxSelect>>", self._on_user_select)
        ttk.Button(sidebar, text="Add Contact", command=self._add_user).pack(fill="x", padx=10, pady=(0,5))
        ttk.Button(sidebar, text="Delete Contact", command=self._delete_user).pack(fill="x", padx=10, pady=(0,5))
        ttk.Button(sidebar, text="Logout", command=self._logout).pack(fill="x", padx=10, pady=(0,10))

        main = tk.Frame(self, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)
        self.status_lbl = tk.Label(main, text="Connecting...", bg=BG, fg=TEXT_DIM, anchor="w", font=("Segoe UI", 9))
        self.status_lbl.grid(row=0, column=0, sticky="ew", padx=10, pady=(8,0))
        self.text_area = tk.Text(main, bg=BG, fg=TEXT, state="disabled", wrap="word", padx=12, pady=12)
        self.text_area.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.text_area.tag_configure("left", justify="left")
        self.text_area.tag_configure("right", justify="right", foreground=ACCENT)

        input_frame = tk.Frame(main, bg=PANEL)
        input_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0,10))
        input_frame.grid_columnconfigure(0, weight=1)
        self.entry = tk.Entry(input_frame, bg="#1c1f27", fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
        self.entry.grid(row=0, column=0, sticky="ew", padx=(10,6), pady=10)
        self.entry.bind("<Return>", self._send_clicked)
        ttk.Button(input_frame, text="Send ➤", command=lambda: self._send_clicked(None)).grid(row=0, column=1, padx=(0,10), pady=10)

    def _populate_users_initial(self):
        for u in self.chat_data.get("users", {}):
            self.user_listbox.insert(tk.END, u)

    # ---------- Networking ----------
    def _auto_register(self):
        try:
            self.client.register(self.app.username)
            self.status_lbl.config(text=f"Registered as '{self.app.username}'")
        except Exception as e:
            messagebox.showerror("Error", f"Register failed: {e}")

    def _logout(self):
        self.client.unregister()
        self.stop_evt.set()
        self.app.username = None
        self.app.password = None
        self.app.key = None
        self.app.show_login_screen()

    # ---------- Message Flow ----------
    def _poll_incoming(self):
        while not self.msg_queue.empty():
            user, text = self.msg_queue.get()
            self._append_message(user, text, "left")
            self.chat_data["users"].setdefault(user, []).append({"from": user, "text": text, "ts": time.time()})
            self._save_encrypted_data()
        self.after(100, self._poll_incoming)

    def _add_user(self):
        name = simpledialog.askstring("Add Contact", "Enter username to connect:")
        if not name:
            return
        if name not in self.chat_data["users"]:
            self.chat_data["users"][name] = []
            self.user_listbox.insert(tk.END, name)
            self._save_encrypted_data()
        self.client.tcp_send_json({"action": "connect", "target": name})
        self.status_lbl.config(text=f"Connecting to {name}...")

    def _delete_user(self):
        sel = self.user_listbox.curselection()
        if not sel:
            return
        user = self.user_listbox.get(sel[0])
        if messagebox.askyesno("Delete", f"Delete chat history with {user}?"):
            del self.chat_data["users"][user]
            self.user_listbox.delete(sel[0])
            self.text_area.config(state="normal")
            self.text_area.delete("1.0", tk.END)
            self.text_area.config(state="disabled")
            self._save_encrypted_data()

    def _on_user_select(self, _evt):
        sel = self.user_listbox.curselection()
        if not sel:
            return
        self.selected_user = self.user_listbox.get(sel[0])
        self._refresh_chat()

    def _refresh_chat(self):
        self.text_area.config(state="normal")
        self.text_area.delete("1.0", tk.END)
        msgs = self.chat_data["users"].get(self.selected_user, [])
        for m in msgs:
            align = "right" if m["from"] == self.app.username else "left"
            self.text_area.insert(tk.END, f"{m['from']}: {m['text']}\n", align)
        self.text_area.config(state="disabled")
        self.text_area.see(tk.END)

    def _send_clicked(self, _):
        text = self.entry.get().strip()
        if not text or not self.selected_user:
            return
        self.entry.delete(0, tk.END)
        self._append_message(self.app.username, text, "right")
        self.chat_data["users"].setdefault(self.selected_user, []).append({"from": self.app.username, "text": text, "ts": time.time()})
        self._save_encrypted_data()
        threading.Thread(target=self.client.send_chat, args=(text,), daemon=True).start()

    def _append_message(self, user, text, align="left"):
        self.text_area.config(state="normal")
        tag = "right" if align == "right" else "left"
        self.text_area.insert(tk.END, f"{user}: {text}\n", tag)
        self.text_area.config(state="disabled")
        self.text_area.see(tk.END)


if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()
