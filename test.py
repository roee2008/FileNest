import os
import hashlib
import typing as t
import customtkinter as ctk
from tkinter import messagebox, filedialog
import socket
from typing import List, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

# ---------- Color Theme ----------
G_BG       = "#0d1117"  # page background
G_PANEL    = "#161b22"  # panels/cards
G_BORDER   = "#30363d"
G_TEXT     = "#c9d1d9"
G_SUBTLE   = "#8b949e"
G_ACCENT   = "#2f81f7"
G_ACCENT_2 = "#3fb950"  # success green

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ---------- Backend API (socket FTP-like) ----------
class SocketBackend:
    def __init__(self, host: str = "127.0.0.1", port: int = 2122, debug: bool = False):
        self.host = host
        self.port = port
        self.password: str = ""
        self.name: str = ""
        self.sock: Optional[socket.socket] = None
        self.debug = debug
        self.aes_key: bytes = None
        self.aes_iv: bytes = None
        self.connect()

    def debug_print(self, message):
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def generate_aes_key(self):
        """Generate a random AES key and IV"""
        self.aes_key = secrets.token_bytes(32)  # 256-bit key
        self.aes_iv = secrets.token_bytes(16)   # 128-bit IV
        return self.aes_key, self.aes_iv
    
    def encrypt_with_aes(self, data: bytes) -> bytes:
        """Encrypt data using AES"""
        if not self.aes_key or not self.aes_iv:
            raise ValueError("AES key not initialized")
        
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad data to multiple of 16 bytes
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def decrypt_with_aes(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES"""
        if not self.aes_key or not self.aes_iv:
            raise ValueError("AES key not initialized")
        
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def encrypt_aes_key_with_rsa(self, aes_key: bytes, aes_iv: bytes) -> bytes:
        """Encrypt AES key and IV with RSA public key"""
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        
        # Combine AES key and IV
        combined_data = aes_key + aes_iv
        
        # Encrypt with RSA
        encrypted = public_key.encrypt(
            combined_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    
    def decrypt_message(self, encrypted_data):
        """
        Decrypt a message that was encrypted with the public key.
        The client needs the private key to decrypt server messages.
        """
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # or b"your_password" if key is encrypted
                backend=default_backend()
            )
        
        # Decrypt the message using the private key
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def connect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.debug_print(f"Connecting to {self.host}:{self.port}")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        try:
            banner = self.sock.recv(1024).decode(errors="ignore")
            self.debug_print(f"Received: {banner.strip()}")
            
            # Generate AES key and send it encrypted with RSA
            aes_key, aes_iv = self.generate_aes_key()
            encrypted_aes_data = self.encrypt_aes_key_with_rsa(aes_key, aes_iv)
            
            # Send encrypted AES key
            self.sock.sendall(encrypted_aes_data)
            self.debug_print("Sent encrypted AES key to server")
            
        except Exception as e:
            self.debug_print(f"Connection error: {e}")
            pass

    def login(self, username: str, password: str) -> bool:
        """Login with username and password. Returns True if successful."""
        password = hashlib.sha256(f'{password}'.encode()).hexdigest()
        self._send(f"LOGIN {username}_{password}")
        response = self._recv_all()
        if "200 LOGIN SUCCESS" in response:
            self.name = username
            self.password = password
            return True
        else:
            return False

    def register(self, username: str, password: str) -> bool:
        """Register with username and password. Returns True if successful."""
        password = hashlib.sha256(f'{password}'.encode()).hexdigest()
        self._send(f"REGISTER {username}_{password}")
        response = self._recv_all()
        if "201 REGISTER SUCCESS" in response:
            self.name = username
            self.password = password
            return True
        else:
            return False

    def logout(self):
        """Logout and clear credentials."""
        self.name = None
        self.password = None

    def is_logged_in(self) -> bool:
        """Check if user is logged in."""
        return self.password != None

    def _send(self, text: str):
        assert self.sock, "Not connected"
        self.debug_print(f"Sent: {text}")
        if self.aes_key and self.aes_iv:
            # Use AES encryption
            encrypted_data = self.encrypt_with_aes(text.encode() + b"\n")
            self.sock.sendall(encrypted_data)
        else:
            # Fallback to plain text (shouldn't happen after key exchange)
            self.sock.sendall(text.encode() + b"\n")

    def _recv_all(self, timeout: float = 0.01) -> str:
        self.sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(None)
        
        if self.aes_key and self.aes_iv and data:
            # Use AES decryption
            try:
                decrypted_data = self.decrypt_with_aes(data)
                decoded_data = decrypted_data.decode(errors="ignore").strip()
            except Exception as e:
                self.debug_print(f"AES decryption failed: {e}")
                decoded_data = data.decode(errors="ignore").strip()
        else:
            # Fallback to plain text
            decoded_data = data.decode(errors="ignore").strip()
        
        self.debug_print(f"Received: {decoded_data}")
        return decoded_data

    def _recv_all_bytes(self, timeout: float = 0.01) -> bytes:
        self.sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(None)
        self.debug_print(f"Received {len(data)} bytes")
        return data

    # --- high-level API for your UI ---
    def list_repos(self) -> List[str]:
        """First-level dirs inside ftp_root are 'repos'."""
        self._send("LIST ")
        raw = self._recv_all()
        if raw.startswith("200 OK"):
            return [line for line in raw.split("\n")[1:] if line]
        return []

    def list_owned_repos(self) -> List[str]:
        """Get repositories owned by the user."""
        self._send("GETREPOS")
        raw = self._recv_all()
        if raw.startswith("200 OK"):
            if len(raw.split("\n")) > 1:
                return raw.split("\n")[1].split(",")
        return []

    def list_files(self, repo: str, path: str = "") -> List[dict]:
        """List inside given repo/path."""
        full_path = os.path.join(repo, path).replace("\\", "/").strip("/")
        self._send(f"LIST {full_path}")
        raw = self._recv_all()
        if raw.startswith("200 OK"):
            items = []
            for name in raw.split("\n")[1:]:
                name = name.strip()
                if not name:
                    continue
                has_extension = bool(os.path.splitext(name)[1])
                items.append({
                    "name": name,
                    "path": f"{path}/{name}".strip("/"),
                    "is_dir": not has_extension
                })
            items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
            return items
        return []

    def get_file(self, repo: str, path: str, version: str = None) -> str:
        full_path = os.path.join(repo, path).replace("\\", "/")
        if version:
            full_path = f"{full_path} {version}"
        self._send(f"GET {full_path}")
        data = self._recv_all()
        if data.startswith("200 OK"):
            return data.split("\n", 1)[1]
        return ""

    def save_file(self, repo: str, path: str, content: str) -> bool:
        full_path = os.path.join(repo, path).replace("\\", "/")
        self._send(f"PUT {full_path}")
        response = self._recv_all()
        if response.startswith("200 OK"):
            self.sock.sendall(content.encode() + b"<EOF>")
            response = self._recv_all()
            return response.startswith("200")
        return False

    def get_file_bytes(self, repo: str, path: str, version: str = None) -> t.Optional[bytes]:
        full_path = os.path.join(repo, path).replace("\\", "/")
        if version:
            full_path = f"{full_path} {version}"
        self._send(f"GET {full_path}")
        data = self._recv_all_bytes()
        if data.startswith(b"200 OK"):
            return data.split(b"\n", 1)[1]
        return None

    def search(self, name: str) -> str:
        self._send(f"SEARCH {name}")
        data = self._recv_all()
        if data.startswith("200 OK"):
            return data.split("\n")[1:]
        return ""

    def mkdir(self, path: str) -> bool:
        full_path = path.replace("\\", "/")
        self._send(f"MKDIR {full_path}")
        response = self._recv_all()
        return response.startswith("201")

    def get_dir(self,  path: str):
        full_path = path.replace("\\", "/")
        self._send(f"GETDIR {full_path}")
        response = self._recv_all()
        if not response.startswith("200 OK"):
            return

        while True:
            header = b""
            while not header.endswith(b"\n"):
                chunk = self.sock.recv(1)
                if not chunk:
                    return
                header += chunk
            header_s = header.decode().strip()
            if header_s == "DONE":
                break
            if header_s.startswith("404"):
                print(header_s)
                break
            _, rel_path, size_str = header_s.split(" ", 2)
            size = int(size_str)
            os.makedirs(os.path.dirname(rel_path), exist_ok=True)
            remaining = size
            data = b""
            while remaining > 0:
                chunk = self.sock.recv(min(4096, remaining))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            with open(rel_path, "wb") as f:
                f.write(data)

    def get_dir_to(self, remote_path: str, dest_root: str):
        remote_path = remote_path.replace("\\", "/").strip("/")
        self._send(f"GETDIR {remote_path}")
        response = self._recv_all()
        if not response.startswith("200 OK"):
            return

        while True:
            header = b""
            while not header.endswith(b"\n"):
                chunk = self.sock.recv(1)
                if not chunk:
                    return
                header += chunk
            header_s = header.decode().strip()
            if header_s == "DONE":
                break
            if header_s.startswith("404"):
                print(header_s)
                break
            _, rel_path, size_str = header_s.split(" ", 2)
            size = int(size_str)
            rel_path = rel_path.replace("\\", "/")
            try:
                rel_to = os.path.relpath(rel_path, remote_path).replace("\\", "/")
            except ValueError:
                rel_to = os.path.basename(rel_path)
            local_path = os.path.join(dest_root, rel_to)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            remaining = size
            with open(local_path, "wb") as f:
                while remaining > 0:
                    chunk = self.sock.recv(min(4096, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)

    def quit(self):
        if not self.sock:
            return
        try:
            self._send("QUIT")
        except ConnectionAbortedError:
            pass
        finally:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def add_user_to_repo(self, repo_name: str, username: str) -> bool:
        """Adds a user to a repository."""
        self._send(f"ADDUSER {repo_name}_{username}")
        response = self._recv_all()
        return response.startswith("200")

    def get_versions(self, repo: str, path: str) -> List[str]:
        """Get available versions for a file."""
        full_path = os.path.join(repo, path).replace("\\", "/")
        self._send(f"GETVERSIONS {full_path}")
        response = self._recv_all()
        if response.startswith("200 OK"):
            versions_line = response.split("\n")[1]
            versions = versions_line.split(',')
            return versions
        return []

# ---------- Utility ----------
class Divider(ctk.CTkFrame):
    def __init__(self, master, height=1, fg=G_BORDER, **kw):
        super().__init__(master, fg_color=fg, height=height, **kw)

# ---------- Login Dialog ----------
class LoginDialog(ctk.CTkToplevel):
    def __init__(self, parent, on_login: t.Callable[[str, str], bool], on_register: t.Callable[[str, str], bool]):
        super().__init__(parent)
        self.on_login = on_login
        self.on_register = on_register
        self.result = False
        self.register_mode = False
        try:
            self.iconbitmap("logo.ico")
        except Exception as e:
            print(f"Error setting icon: {e}")
        # Configure window
        self.title("Login")
        self.geometry("300x300")  # Increased height for confirm password
        self.resizable(False, False)
        self.configure(fg_color=G_BG)

        
        # Center the dialog
        self.transient(parent)
        self.grab_set()
        
        # Create widgets
        self._create_widgets()
        
        # Center on parent
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _create_widgets(self):
        # Title
        self.title_label = ctk.CTkLabel(self, text="Login", font=("Inter", 16, "bold"), text_color=G_TEXT)
        self.title_label.pack(pady=(20, 10))
        
        # Username
        self.username_label = ctk.CTkLabel(self, text="Username:", text_color=G_TEXT)
        self.username_label.pack(anchor="w", padx=20)
        
        self.username_entry = ctk.CTkEntry(self, placeholder_text="Enter username", fg_color=G_PANEL, border_color=G_BORDER)
        self.username_entry.pack(fill="x", padx=20, pady=(0, 10))
        
        # Password
        self.password_label = ctk.CTkLabel(self, text="Password:", text_color=G_TEXT)
        self.password_label.pack(anchor="w", padx=20)
        
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Enter password", show="*", fg_color=G_PANEL, border_color=G_BORDER)
        self.password_entry.pack(fill="x", padx=20, pady=(0, 10))
        
        # Buttons
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        self.submit_btn = ctk.CTkButton(
            button_frame, 
            text="Login", 
            fg_color=G_ACCENT, 
            hover_color="#1f6feb",
            command=self._submit
        )
        self.submit_btn.pack(side="left", padx=(0, 10))
        
        self.cancel_btn = ctk.CTkButton(
            button_frame, 
            text="Cancel", 
            fg_color=G_PANEL, 
            hover_color="#1f2937",
            command=self._cancel
        )
        self.cancel_btn.pack(side="right")

        # Switch link
        self.switch_link = ctk.CTkLabel(self, text="Don't have an account? Register", text_color=G_ACCENT, cursor="hand2")
        self.switch_link.pack(pady=10)
        self.switch_link.bind("<Button-1>", lambda e: self._toggle_mode())
        
        # Bind Enter key to login
        self.bind("<Return>", lambda e: self._submit())
        self.bind("<Escape>", lambda e: self._cancel())
        
        # Focus on username entry
        self.username_entry.focus()

    def _toggle_mode(self):
        self.register_mode = not self.register_mode
        if self.register_mode:
            self.title_label.configure(text="Register")
            self.submit_btn.configure(text="Register")
            self.switch_link.configure(text="Already have an account? Login")
        else:
            self.title_label.configure(text="Login")
            self.submit_btn.configure(text="Login")
            self.switch_link.configure(text="Don't have an account? Register")

    def _submit(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password")
            return

        if self.register_mode:
            try:
                success = self.on_register(username, password)
                if success:
                    self.result = True
                    self.destroy()
                else:
                    messagebox.showerror("Registration Failed", "Registration failed. Please try again.")
            except Exception as e:
                messagebox.showerror("Registration Error", f"Registration failed: {str(e)}")
        else:
            try:
                success = self.on_login(username, password)
                if success:
                    self.result = True
                    self.destroy()
                else:
                    messagebox.showerror("Login", "Login failed. Please check your credentials.")
            except Exception as e:
                messagebox.showerror("Login Error", f"Login failed: {str(e)}")

    def _cancel(self):
        self.destroy()

    def get_result(self) -> bool:
        """Return True if login was successful, False otherwise."""
        return self.result



# ---------- Top Bar ----------
class TopBar(ctk.CTkFrame):
    def __init__(self, master, on_search: t.Callable[[str], None], on_login: t.Callable[[], None]):
        super().__init__(master, fg_color=G_PANEL)
        self.grid_columnconfigure(1, weight=1)
        self.on_login = on_login
        self.master = master
        self.search_timer = None

        self.logo = ctk.CTkLabel(self, text="", font=("Segoe UI Symbol", 22), text_color=G_TEXT)
        self.logo.grid(row=0, column=0, padx=(12, 8), pady=10)

        self.search = ctk.CTkEntry(self, placeholder_text="Search…", fg_color=G_BG, border_color=G_BORDER)
        self.search.grid(row=0, column=1, sticky="ew", padx=6, pady=10)
        self.search.bind("<KeyRelease>", lambda e: self._on_search_delayed(on_search))
        self.logo.grid(row=0, column=3, padx=(6, 12))

        self.avatar = ctk.CTkLabel(self, text="", width=34, height=34, corner_radius=17,
                                   fg_color=G_BG, text_color=G_TEXT, font=("Inter", 12, "bold"))
        self.avatar.grid(row=0, column=3, padx=(6, 12))
        # Bind click event to avatar for login
        self.avatar.bind("<Button-1>", lambda e: self.on_login())

    def _on_search_delayed(self, on_search):
        if self.search_timer:
            self.master.after_cancel(self.search_timer)
        self.search_timer = self.master.after(1, lambda: on_search(self.search.get()))

    def update_avatar(self, username: str = None):
        """Update avatar text with user initials or default 'RO'"""
        if username:
            self.avatar.configure(text=username[0].capitalize())
        else:
            self.avatar.configure(text="RO")

# ---------- Sidebar ----------
class SideBar(ctk.CTkFrame):
    def __init__(self, master, on_nav: t.Callable[[str], None], on_refresh_repos: t.Callable[[], None]):
        super().__init__(master, fg_color=G_PANEL, corner_radius=0)
        self.on_nav = on_nav
        self.buttons: dict[str, ctk.CTkButton] = {}
        items = [
            ("Home", "Home"),
            ("Repositories", "Explorer"),
            ("Account", "Account"),
        ]
        for i, (key, label) in enumerate(items):
            ctk.CTkButton(
                self, text=label, fg_color="transparent", hover_color="#0f172a",
                corner_radius=8, anchor="w", command=lambda k=key: self.on_nav(k)
            ).pack(fill="x", padx=10, pady=(8 if i == 0 else 4, 0))

        Divider(self).pack(fill="x", padx=10, pady=10)

        repo_header = ctk.CTkFrame(self, fg_color="transparent")
        repo_header.pack(fill="x", padx=10, pady=(0, 4))
        self.repo_label = ctk.CTkLabel(repo_header, text="Repositories", text_color=G_SUBTLE)
        self.repo_label.pack(side="left")

        self.refresh_btn = ctk.CTkButton(repo_header, text="🔄", width=28, height=28, fg_color="transparent", hover_color="#0f172a", command=on_refresh_repos)
        self.refresh_btn.pack(side="right")

        self.repo_list = ctk.CTkScrollableFrame(self, fg_color=G_BG)
        self.repo_list.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def populate_repos(self, repos: list[str], on_click_repo: t.Callable[[str], None]):
        #print(f"DEBUG: Populating repos: {repos}")
        for w in self.repo_list.winfo_children():
            w.destroy()
        for r in repos:
            btn = ctk.CTkButton(self.repo_list, text=r, fg_color=G_PANEL, hover_color="#1f2937",
                                 corner_radius=6, command=lambda name=r: on_click_repo(name))
            btn.pack(fill="x", padx=6, pady=4)

# ---------- Cards & Tiles ----------
class RepoCard(ctk.CTkFrame):
    def __init__(self, master, name: str, desc: str = None, on_open: t.Callable[[], None] = None):
        super().__init__(master, fg_color=G_PANEL, corner_radius=12, border_width=1, border_color=G_BORDER)
        self.grid_columnconfigure(1, weight=1)
        icon = ctk.CTkLabel(self, text="\uf1c9", font=("Segoe UI Symbol", 20), text_color=G_SUBTLE)
        icon.grid(row=0, column=0, padx=12, pady=12, sticky="n")
        title = ctk.CTkLabel(self, text=name, font=("Inter", 14, "bold"))
        title.grid(row=0, column=1, sticky="w", pady=(12, 0))
        subtitle = ctk.CTkLabel(self, text=desc or "No description", text_color=G_SUBTLE)
        subtitle.grid(row=1, column=1, sticky="w", pady=(2, 12))
        open_btn = ctk.CTkButton(self, text="Open", fg_color=G_ACCENT, hover_color="#1f6feb",
                                 command=on_open)
        open_btn.grid(row=0, column=2, rowspan=2, padx=12, pady=12)

# ---------- Explorer (File Tree) ----------
class Explorer(ctk.CTkFrame):
    def __init__(self, master, backend, on_open_file: t.Callable[[str, Optional[str]], None]):
        super().__init__(master, fg_color=G_BG)
        self.backend = backend
        self.repo: str = None
        self.path = ""
        self.on_open_file = on_open_file

        # Breadcrumbs
        self.breadcrumb = ctk.CTkLabel(self, text="", text_color=G_SUBTLE)
        self.breadcrumb.pack(anchor="w", padx=8, pady=(8, 4))
        
        # Status bar
        self.status = ctk.CTkLabel(self, text="Right-click items marked with ❓ to try opening as file",
                                    text_color=G_SUBTLE, font=("Inter", 10))
        self.status.pack(anchor="w", padx=8, pady=(0, 4))

        # File list
        self.list = ctk.CTkScrollableFrame(self, fg_color=G_PANEL, border_color=G_BORDER, border_width=1,
                                           corner_radius=12)
        self.list.pack(fill="both", expand=True, padx=8, pady=8)
        self._render_empty()

    def _do_download(self, p, fname, isdir, version=None):
        if isdir:
            dest_dir = filedialog.askdirectory(title=f"Choose folder to save '{fname}'")
            if not dest_dir:
                return
            self.backend.get_dir_to(f"{self.repo}/{p}".strip("/"), dest_dir)
        else:
            print(f"Downloading file: {p} version: {version}")
            data = self.backend.get_file_bytes(self.repo, p, version)
            if data is None:
                messagebox.showwarning("Download", f"Cannot download: {p}")
                return
            dst = filedialog.asksaveasfilename(initialfile=fname)
            if not dst:
                return
            with open(dst, "wb") as f:
                f.write(data)

    def open_repo(self, repo: str,path: str = ""):
        self.repo = repo
        self.path = path
        self.refresh()

    def _container(self):
        # use inner content frame if it exists, else the frame itself
        return getattr(self.list, "scrollable_frame", self.list)

    def _render_empty(self):
        container = self._container()
        for w in container.winfo_children():
            w.destroy()
        ctk.CTkLabel(container, text="Select a repository from the left.", text_color=G_SUBTLE).pack(pady=20)

    def refresh(self):
        max_length: int = 15
        if not self.repo:
            self._render_empty()
            return

        # FIX: include repo
        entries = self.backend.list_files(self.repo, self.path)
        # Check if the list is not empty before accessing its elements
        if not entries:
            pass # entries is already an empty list, which is handled below
        container = self._container()
        for w in container.winfo_children():
            w.destroy()

        if self.path:
            ctk.CTkButton(container, text="..", fg_color="transparent", hover_color="#0f172a",
                          anchor="w", command=self._go_up).pack(fill="x", padx=6, pady=(6, 0))
        if not entries: 
            ctk.CTkLabel(container, text="(Empty)", text_color=G_SUBTLE).pack(pady=10)
            return # Stop here if there are no entries

        for e in entries: # This loop will now only run if entries is not empty
            name = e["name"]
            text, ext = os.path.splitext(name)
            if len(name) >= max_length:
                allowed_name_length = max_length - len(ext)

                # If extension itself is too long, just truncate everything
                if allowed_name_length <= 0:
                    name = name[:max_length]

                name = text[:allowed_name_length] + ext
            rel_path = e["path"]
            is_dir = bool(e["is_dir"])

            # Add a context menu or double-click to try opening as file if it's marked as directory
            if "." not in name:
                label = "📁 " + name
            else:
                label = "📄 " + name
            
            def create_open_cmd(p=rel_path, isdir=is_dir):
                if isdir:
                    return lambda: self._open_dir(p)
                else:
                    return lambda: self.on_open_file(p, None)
            
            open_cmd = create_open_cmd()

            row = ctk.CTkFrame(container, fg_color="transparent")
            row.pack(fill="x", padx=6, pady=2)

            file_btn = ctk.CTkButton(
                row, text=label, fg_color="transparent", hover_color="#0f172a",
                anchor="w",width=130, command=open_cmd
            )
            file_btn.pack(side="left", fill="x", expand=True)
            
            # Add right-click context menu for items marked as directories
            if is_dir:
                def try_as_file(p=rel_path):
                    try:
                        # Try to open as file first
                        self.on_open_file(p, None)
                    except Exception as e:
                        # If that fails, open as directory
                        print(f"Failed to open {p} as file, trying as directory: {e}")
                        self._open_dir(p)
                
                # Bind right-click to try opening as file
                file_btn.bind("<Button-3>", lambda e, p=rel_path: try_as_file(p))

            if not is_dir:
                versions = self.backend.get_versions(self.repo, rel_path)
                if versions:
                    latest_version = versions[-1]
                    
                    # This variable will hold the selected version from the dropdown.
                    # It's initialized to the latest version.
                    selected_version_var = ctk.StringVar(value=latest_version)

                    # Command for the dropdown to open the selected version.
                    open_version_command = lambda chosen_version, p=rel_path: self.on_open_file(p, version=chosen_version)
                    
                    actions_frame = ctk.CTkFrame(row, fg_color="transparent")
                    actions_frame.pack(side="right", padx=(6, 0))
                    # The download button's command now reads the version from the shared variable.
                    download_button = ctk.CTkButton(actions_frame, text="⬇", width=30, fg_color=G_ACCENT, hover_color="#1f6feb",
                                  command=lambda p=rel_path, f=name, isd=is_dir, var=selected_version_var: self._do_download(p, f, isd, var.get()))
                    download_button.pack(side="left")

                    version_menu = ctk.CTkOptionMenu(actions_frame, values=versions, command=open_version_command, width=10, fg_color=G_ACCENT, variable=selected_version_var)
                    version_menu.pack(side="left", padx=(2, 0))

        crumb = self.repo + (f" / {self.path}" if self.path else "")
        self.breadcrumb.configure(text=crumb)
        #print("DEBUG LIST:", self.repo, self.path, entries)

    def _go_up(self):
        if not self.path:
            return
        parts = self.path.split('/')
        self.path = '/'.join(parts[:-1])
        self.refresh()

    def _open_dir(self, path: str):
        self.path = path
        self.refresh()

# ---------- Editor (Tabs + Text) ----------
class Editor(ctk.CTkFrame):
    def __init__(self, master, backend, repo_getter: t.Callable[[], str]):
        super().__init__(master, fg_color=G_BG)
        self.backend = backend
        self.repo_getter = repo_getter
        self.tabs: dict[str, ctk.CTkButton] = {}
        self.active_path: str = None

        # Tabs bar
        self.tab_bar = ctk.CTkScrollableFrame(self, fg_color=G_PANEL, height=40, corner_radius=15, border_color=G_BORDER, border_width=1, orientation="horizontal")
        self.tab_bar.pack(fill="x", padx=8, pady=(8, 0))

        # Editor area
        self.text = ctk.CTkTextbox(self, fg_color=G_PANEL, border_color=G_BORDER, border_width=1,
                                   text_color=G_TEXT, font=("JetBrains Mono", 12))
        self.text.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        # Status bar
        self.status = ctk.CTkLabel(self, text="Ready", text_color=G_SUBTLE)
        self.status.pack(anchor="w", padx=10, pady=6)

        # Bindings
        self.text.bind("<KeyRelease>", self._on_changed)

    def open_file(self, path: str, version: str = None):
        repo = self.repo_getter()
        if not repo:
            messagebox.showwarning("Open", "No repository selected")
            return
        try:
            content = self.backend.get_file(repo, path, version=version)
            if content == "":
                messagebox.showwarning("Open", f"Cannot open: {path}")
                return
            # Create tab if needed
            tab_text = path
            if version:
                tab_text = f"{path} (V{version})"
            if path not in self.tabs:
                btn = ctk.CTkButton(self.tab_bar, text=tab_text, fg_color=G_BG, hover_color="#0f172a",
                                     corner_radius=6, command=lambda p=path: self.open_file(p))
                btn.pack(side="left", padx=4, pady=6)
                self.tabs[path] = btn
            else:
                self.tabs[path].configure(text=tab_text)
            self._activate(path)
            self.text.delete("0.0", "end" )
            self.text.insert("0.0", content)
            self.status.configure(text=f"Opened {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open {path}: {str(e)}")

    def _activate(self, path: str):
        self.active_path = path
        for p, b in self.tabs.items():
            b.configure(fg_color=(G_ACCENT if p == path else G_BG))

    def _on_changed(self, _event=None):
        if self.active_path:
            self.status.configure(text=f"Editing {self.active_path} – Unsaved changes…")

    def save_active(self):
        repo = self.repo_getter()
        if not (repo and self.active_path):
            return
        content = self.text.get("1.0", "end-1c")
        ok = self.backend.save_file(repo, self.active_path, content)
        if ok:
            self.status.configure(text=f"Saved {self.active_path} ✓")
        else:
            self.status.configure(text=f"Failed to save {self.active_path}")

# ---------- Main Views ----------
class HomeView(ctk.CTkScrollableFrame):
    def __init__(self, master, backend: SocketBackend, on_open_repo: t.Callable[[str], None]):
        super().__init__(master, fg_color=G_BG)
        ctk.CTkLabel(self, text="Overview", font=("Inter", 18, "bold")).pack(anchor="w", padx=8, pady=(8, 4))
        grid = ctk.CTkFrame(self, fg_color=G_BG)
        grid.pack(fill="both", expand=False, padx=6, pady=4)
        grid.grid_columnconfigure((0,1), weight=1)
        repos = backend.list_repos()
        for i, r in enumerate(repos):
            card = RepoCard(grid, r, "Remote server", on_open=lambda name=r: on_open_repo(name))
            card.grid(row=i//2, column=i%2, sticky="ew", padx=6, pady=6)
    

class ExplorerView(ctk.CTkFrame):
    def __init__(self, master, backend: SocketBackend):
        super().__init__(master, fg_color=G_BG)
        self.backend = backend

        # Toolbar
        bar = ctk.CTkFrame(self, fg_color=G_PANEL)
        bar.pack(fill="x")

        # Content split
        split = ctk.CTkFrame(self, fg_color=G_BG)
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=1, uniform="x")
        split.grid_columnconfigure(1, weight=2, uniform="x")

        # Create children inside split
        self.explorer = Explorer(split, backend, on_open_file=self._open_in_editor)
        self.editor   = Editor(split, backend, repo_getter=lambda: self.explorer.repo)

        self.explorer.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        self.editor.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)

        # Toolbar buttons (now bound to self.explorer/self.editor)
        btn_refresh = ctk.CTkButton(bar, text="Refresh", fg_color=G_BG, hover_color="#0f172a",
                                    command=self.explorer.refresh)
        btn_refresh.pack(side="left", padx=6, pady=6)

        def do_mkdir():
            repo = self.explorer.repo
            if not repo:
                return
            name = ctk.CTkInputDialog(text="Folder name:", title="New folder").get_input()
            if not name:
                return
            rel = "/".join([p for p in [self.explorer.path, name] if p])
            backend.mkdir("/".join([self.explorer.repo, rel]).strip("/"))
            self.explorer.refresh()

        def do_put():
            filepath = filedialog.askopenfilename()
            if not filepath:
                return
            remote_path = "/".join([p for p in [self.explorer.path, os.path.basename(filepath)] if p])
            full_remote = "/".join([self.explorer.repo, remote_path]).strip("/")
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                backend._send(f"PUT {full_remote}")
                try:
                    _ = backend.sock.recv(1024)
                except Exception:
                    pass
                backend.sock.sendall(data + b"<EOF>")
                try:
                    _ = backend.sock.recv(1024)
                except Exception:
                    pass
            except Exception as e:
                messagebox.showerror("Upload failed", str(e))
            self.explorer.refresh()

        def do_getdir():
            backend.get_dir(self.explorer.path)

        ctk.CTkButton(bar, text="New Folder", fg_color=G_BG, hover_color="#0f172a", command=do_mkdir)	.pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bar, text="Upload File", fg_color=G_BG, hover_color="#0f172a", command=do_put)	.pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bar, text="Download Dir", fg_color=G_BG, hover_color="#0f172a", command=do_getdir)	.pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bar, text="Save (Ctrl+S)", fg_color=G_ACCENT, hover_color="#1f6feb",
                      command=self.editor.save_active).pack(side="right", padx=6, pady=6)

        Divider(self).pack(fill="x")

    def _open_in_editor(self, path: str, version: str = None):
        self.editor.open_file(path, version)

class AccountView(ctk.CTkFrame):
    def __init__(self, master, backend: SocketBackend):
        super().__init__(master, fg_color=G_BG)
        self.backend = backend
        self.selected_repo = None

        # Configure grid layout: 3 columns
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)
        self.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(self, text="Account Settings", font=("Inter", 18, "bold")).grid(row=0, column=0, columnspan=3, padx=8, pady=(8, 4), sticky="ew")

        # --- Left Column ---
        left_column = ctk.CTkFrame(self, fg_color="transparent")
        left_column.grid(row=1, column=0, sticky="nsew", padx=(16, 0), pady=4)
        left_column.grid_rowconfigure(0, weight=1)

        # Repo list
        self.scrollable_frame = ctk.CTkScrollableFrame(left_column, label_text="Your Repositories", fg_color=G_PANEL, border_color=G_BORDER, border_width=1, width=300)
        self.scrollable_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 8))

        # Add user section
        self.add_user_frame = ctk.CTkFrame(left_column, fg_color="transparent")
        self.add_user_frame.grid(row=1, column=0, sticky="ew", pady=4)
        self.add_user_frame.grid_columnconfigure(0, weight=1)

        self.user_to_add_entry = ctk.CTkEntry(self.add_user_frame, placeholder_text="Username to add")
        self.user_to_add_entry.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self.add_user_button = ctk.CTkButton(self.add_user_frame, text="Add User", command=self.add_user)
        self.add_user_button.grid(row=0, column=1, sticky="e")
        
        # Initially hide the add user frame
        self.add_user_frame.grid_remove()

        # --- Middle and Right Columns ---
        right_panel = ctk.CTkFrame(self, fg_color="transparent")
        right_panel.grid(row=1, column=1, columnspan=2, sticky="nsew", padx=(0, 8), pady=4)
        right_panel.grid_columnconfigure(0, weight=1)

        # Settings Frame
        settings_frame = ctk.CTkFrame(right_panel, fg_color=G_PANEL, border_color=G_BORDER, border_width=1)
        settings_frame.grid(row=0, column=0, sticky="new", padx=4, pady=0)
        settings_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(settings_frame, text="Account Actions", font=("Inter", 14, "bold")).grid(row=0, column=0, padx=12, pady=(12, 8), sticky="w")

        # Change Password
        ctk.CTkButton(settings_frame, text="Change Password", anchor="w", fg_color="transparent"
                      , hover=False).grid(row=1, column=0, sticky="ew", padx=12, pady=4)
        
        # Logout
        ctk.CTkButton(settings_frame, text="Logout", anchor="w", fg_color="transparent"
                      , hover=False).grid(row=2, column=0, sticky="ew", padx=12, pady=4)

        # Delete Account (with warning color)
        ctk.CTkButton(settings_frame, text="Delete Account", anchor="w", text_color="#f85149", fg_color="transparent"
                      , hover=False).grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 12))


    def refresh(self):
        # Clear existing repos
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        # Get repositories from the server
        repos = self.backend.list_owned_repos()

        for repo in repos:
            repo_frame = ctk.CTkFrame(self.scrollable_frame, fg_color="transparent")
            repo_frame.pack(pady=5, padx=5, fill="x")
            repo_label = ctk.CTkLabel(repo_frame, text=repo)
            repo_label.pack(side="left", padx=5)
            select_button = ctk.CTkButton(repo_frame, text="Select", command=lambda r=repo: self.select_repo(r))
            select_button.pack(side="right", padx=5)
        
        # Hide the add user frame on refresh
        self.add_user_frame.grid_remove()

    def select_repo(self, repo_name):
        self.selected_repo = repo_name
        self.add_user_frame.grid() # Show the add user section

    def add_user(self):
        user_to_add = self.user_to_add_entry.get()
        if user_to_add and self.selected_repo:
            if self.backend.add_user_to_repo(self.selected_repo, user_to_add):
                messagebox.showinfo("Success", f"User {user_to_add} added to {self.selected_repo}")
            else:
                messagebox.showerror("Error", f"Failed to add user {user_to_add} to {self.selected_repo}")

# ---------- App ----------
class App(ctk.CTk):
    def __init__(self, backend: SocketBackend = None):
        super().__init__()
        self.backend = backend or SocketBackend()
        self.title("FileNest")
        self.geometry("1100x700")
        self.minsize(900, 560)
        self.iconbitmap("logo.ico")
        self.configure(fg_color=G_BG)
        dialog = LoginDialog(self, self._on_login, self._on_register)
        dialog.wait_window()
        self.searchFrame = None
        self.file_buttons = []
        # Layout grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Top bar
        self.top = TopBar(self, self._on_search, self._login_dialog)
        self.top.grid(row=0, column=0, columnspan=2, sticky="ew")
        
        # Divider
        Divider(self).grid(row=1, column=0, columnspan=2, sticky="ew")
        # Sidebar
        self.sidebar = SideBar(self, self._on_nav, self._refresh_repo_list)
        self.sidebar.grid(row=2, column=0, sticky="nsw")
        self.sidebar.configure(width=250)
        self.sidebar.grid_propagate(False)
        self.sidebar.populate_repos(self.backend.list_repos(), self._open_repo_from_sidebar)

        # Main area (stacked views)
        self.stack = ctk.CTkFrame(self, fg_color=G_BG)
        self.stack.grid(row=2, column=1, sticky="nsew")
        self.stack.grid_rowconfigure(0, weight=1)
        self.stack.grid_columnconfigure(0, weight=1)

        # Views
        self.view_home = HomeView(self.stack, self.backend, on_open_repo=self._open_repo)
        self.view_explorer = ExplorerView(self.stack, self.backend)
        self.view_account = AccountView(self.stack, self.backend)

        # Use explorer/editor created inside ExplorerView
        self.explorer = self.view_explorer.explorer
        self.editor   = self.view_explorer.editor

        # Place default view
        self._show(self.view_home)
        
        # Shortcuts
        self.bind_all("<Control-s>", lambda e: self.editor.save_active())

    # ----- Navigation & helpers -----
    def _show(self, widget: ctk.CTkBaseClass):
        for w in self.stack.winfo_children():
            w.grid_forget()
        widget.grid(row=0, column=0, sticky="nsew")

    def _on_nav(self, key: str):
        if key in ("Home",):
            self._show(self.view_home)
        elif key in ("Repositories",):
            self._show(self.view_explorer)
        elif key in ("Account",):
            self.view_account.refresh()
            self._show(self.view_account)

    def _on_search(self, query: str):
        if query=="":
            self.file_buttons.clear()
            for w in self.searchFrame.winfo_children():
                w.destroy()
        if self.searchFrame is None:
            self.searchFrame = ctk.CTkFrame(self, fg_color="transparent", border_color=G_BORDER,width=1, height=1, border_width=2)
            self.searchFrame.place(x=5, y=10)
            self.searchFrame.lift()

        for w in self.searchFrame.winfo_children():
            w.destroy()
        self.file_buttons.clear()

        max_length = 200
        filepath = self.backend.search(query)

        if filepath and filepath != "No files found.":
            for e in filepath:
                name = e[:max_length]

                row = ctk.CTkFrame(self.searchFrame, fg_color="transparent", corner_radius=0)
                row.pack(fill="x", padx=6, pady=2)

                file_btn = ctk.CTkButton(
                    row, text=name, fg_color="transparent", hover_color="#0f172a", corner_radius=0,
                    anchor="w", command=lambda e=e: self._search_open(e)
                )
                file_btn.pack(side="left", fill="x", expand=True)
                self.file_buttons.append(file_btn)
    
    def _search_open(self,file: str):
        file=file.split("/", 1)
        repo_name = file[0]
        path_in_repo = file[1] if len(file) > 1 else ""
        print(file ,path_in_repo)

        # Open the repository
        self._open_repo(repo_name)

        # 1. Navigate to the repository in the explorer
        if "/" in path_in_repo:
            self.explorer.open_repo(repo_name, path_in_repo.rsplit("/", 1)[0])
        else:
            self.explorer.open_repo(repo_name, "")
        # 2. Open the file in the editor
        self.editor.open_file(path_in_repo) # editor.open_file expects path relative to the current repo

        # 3. Activate the editor tab for the file
        self.editor._activate(path_in_repo)

        # 4. Refresh the explorer to show the file
        self.explorer.refresh()

    def _login_dialog(self):
        dialog = LoginDialog(self, self._on_login, self._on_register)
        dialog.wait_window()  # Wait for dialog to close
        if dialog.get_result():
            # Update avatar with logged-in user's initials
            if self.backend.name:
                self.top.update_avatar(self.backend.name)
            self.sidebar.populate_repos(self.backend.list_repos(), self._open_repo_from_sidebar)

    def _refresh_repo_list(self):
        try:
            repos = self.backend.list_repos()
            self.sidebar.populate_repos(repos, self._open_repo_from_sidebar)
        except Exception as e:
            messagebox.showerror("Refresh Error", f"Failed to refresh repositories: {str(e)}")

    def _on_login(self, username: str, password: str) -> bool:
        return self.backend.login(username, password)

    def _on_register(self, username: str, password: str) -> bool:
        return self.backend.register(username, password)

    def _open_repo(self, name: str):
        self.sidebar.on_nav("Repositories")
        self._show(self.view_explorer)
        self.explorer.open_repo(name)

    def _open_repo_from_sidebar(self, name: str):
        self._open_repo(name)

    def on_closing(self):
        try:
            self.backend.quit()
        finally:
            self.destroy()

# ---------- Run ----------

if __name__ == "__main__":
    print("Starting app...")
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()