"""
securevault.py  —  SecureVault Password Manager (self-contained)
=================================================================
Module : ST5062CEM - Programming and Algorithm 2
CW2    : Individual Project

Everything in one file — no separate imports needed.
Run: python securevault.py

Install dependency first:
    pip install cryptography

Security features:
  - Master password hashed with SHA-256 + random salt (never stored plain)
  - All vault passwords encrypted with Fernet symmetric encryption
  - SQL injection prevention via parameterised queries only
  - Passwords decrypted only on explicit user request
  - Lock button clears encryption key from memory
"""

# ── Startup guard ─────────────────────────────────────────────────────────────
import sys

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ModuleNotFoundError:
    sys.exit(
        "\n[ERROR] tkinter not found.\n"
        "  Windows : reinstall Python and tick 'tcl/tk and IDLE'\n"
        "  Ubuntu  : sudo apt install python3-tk\n"
        "  macOS   : brew install python-tk\n"
    )

try:
    from cryptography.fernet import Fernet
except ModuleNotFoundError:
    sys.exit(
        "\n[ERROR] cryptography library not found.\n"
        "  Install it with:  pip install cryptography\n"
    )

import os
import csv
import random
import sqlite3
import hashlib
import secrets
import string
from datetime import datetime

# =============================================================================
# SECTION 1 — CUSTOM DATA STRUCTURES
# =============================================================================

class PasswordEntry:
    """
    Value object representing a single password vault entry.

    Attributes
    ----------
    entry_id           : int  — unique database ID
    site               : str  — website or application name
    username           : str  — username or email address
    encrypted_password : str  — Fernet-encrypted password
    created_at         : str  — creation timestamp
    """

    def __init__(self, entry_id, site, username, encrypted_password, created_at=None):
        self.entry_id           = entry_id
        self.site               = site
        self.username           = username
        self.encrypted_password = encrypted_password
        self.created_at         = created_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def __repr__(self):
        return (f"PasswordEntry(id={self.entry_id}, "
                f"site={self.site!r}, username={self.username!r})")


class EntryList:
    """
    User-defined singly-linked list for PasswordEntry objects.

    Uses a hand-rolled linked list rather than Python's built-in list,
    satisfying the coursework requirement for custom data structures.

    Complexity
    ----------
    append         : O(n)  — walks to tail
    remove_by_id   : O(n)  — linear scan
    find_by_site   : O(n)  — linear scan
    to_sorted_list : O(n²) — insertion sort by site name
    clear          : O(1)
    """

    class _Node:
        __slots__ = ("data", "next")
        def __init__(self, data):
            self.data = data
            self.next = None

    def __init__(self):
        self._head = None
        self._size = 0

    def append(self, data):
        """Append entry at the tail. O(n)."""
        node = self._Node(data)
        if self._head is None:
            self._head = node
        else:
            cur = self._head
            while cur.next:
                cur = cur.next
            cur.next = node
        self._size += 1

    def remove_by_id(self, entry_id):
        """Remove by entry_id. Returns True if found. O(n)."""
        if self._head is None:
            return False
        if self._head.data.entry_id == entry_id:
            self._head = self._head.next
            self._size -= 1
            return True
        cur = self._head
        while cur.next:
            if cur.next.data.entry_id == entry_id:
                cur.next = cur.next.next
                self._size -= 1
                return True
            cur = cur.next
        return False

    def find_by_site(self, query):
        """Case-insensitive substring search. O(n)."""
        results = []
        cur = self._head
        while cur:
            if query.lower() in cur.data.site.lower():
                results.append(cur.data)
            cur = cur.next
        return results

    def to_sorted_list(self):
        """
        Return all entries sorted alphabetically by site name.
        Uses insertion sort — O(n²) — to demonstrate custom algorithm.
        """
        items = []
        cur = self._head
        while cur:
            items.append(cur.data)
            cur = cur.next
        # Insertion sort
        for i in range(1, len(items)):
            key = items[i]
            j   = i - 1
            while j >= 0 and items[j].site.lower() > key.site.lower():
                items[j + 1] = items[j]
                j -= 1
            items[j + 1] = key
        return items

    def to_list(self):
        """Return entries in insertion order."""
        items = []
        cur   = self._head
        while cur:
            items.append(cur.data)
            cur = cur.next
        return items

    def clear(self):
        """Reset to empty. O(1)."""
        self._head = None
        self._size = 0

    def __len__(self):
        return self._size


# =============================================================================
# SECTION 2 — VAULT CORE
# =============================================================================

class VaultCore:
    """
    Core password manager logic.

    Security model
    --------------
    1. Master password → SHA-256(password + random_salt) stored in DB.
       Plain password is never persisted anywhere.
    2. Fernet key stored in DB, only accessible after authentication gate.
    3. Individual passwords encrypted with Fernet before DB insert.
    4. Decryption happens only on explicit user request.
    5. lock() clears the Fernet instance from memory.
    6. All DB queries use ? placeholders — no string formatting in SQL.
    """

    def __init__(self, db_path="vault.db"):
        self.db_path  = db_path
        self._fernet  = None
        self._entries = EntryList()
        self._init_db()

    def _init_db(self):
        """Create tables if not present."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS master (
                    id            INTEGER PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt          TEXT NOT NULL,
                    fernet_key    TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    site               TEXT NOT NULL,
                    username           TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    created_at         TEXT NOT NULL
                )
            """)
            conn.commit()

    def is_setup(self):
        """True if master password has been configured."""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM master").fetchone()[0] > 0

    def setup_master(self, master_password):
        """Hash and store master password with a random salt. Generate Fernet key."""
        if len(master_password) < 6:
            raise ValueError("Master password must be at least 6 characters.")
        salt   = secrets.token_hex(32)
        h      = hashlib.sha256((master_password + salt).encode()).hexdigest()
        fkey   = Fernet.generate_key().decode()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM master")
            conn.execute(
                "INSERT INTO master (password_hash, salt, fernet_key) VALUES (?, ?, ?)",
                (h, salt, fkey)
            )
            conn.commit()

    def authenticate(self, master_password):
        """Verify master password and load Fernet key. Returns bool."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT password_hash, salt, fernet_key FROM master"
            ).fetchone()
        if not row:
            return False
        stored_hash, salt, fernet_key = row
        computed = hashlib.sha256((master_password + salt).encode()).hexdigest()
        if computed == stored_hash:
            self._fernet = Fernet(fernet_key.encode())
            return True
        return False

    def lock(self):
        """Clear encryption key from memory (secure logout)."""
        self._fernet = None
        self._entries.clear()

    def encrypt_password(self, plaintext):
        if not self._fernet:
            raise RuntimeError("Vault locked.")
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt_password(self, ciphertext):
        if not self._fernet:
            raise RuntimeError("Vault locked.")
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def add_entry(self, site, username, password):
        encrypted  = self.encrypt_password(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO entries (site, username, encrypted_password, created_at) "
                "VALUES (?, ?, ?, ?)",
                (site, username, encrypted, created_at)
            )
            entry_id = cur.lastrowid
            conn.commit()
        entry = PasswordEntry(entry_id, site, username, encrypted, created_at)
        self._entries.append(entry)
        return entry

    def delete_entry(self, entry_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            conn.commit()
        self._entries.remove_by_id(entry_id)

    def load_entries(self):
        self._entries.clear()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, site, username, encrypted_password, created_at FROM entries"
            ).fetchall()
        for row in rows:
            self._entries.append(PasswordEntry(*row))
        return self._entries.to_list()

    def get_all_entries(self):
        return self._entries.to_sorted_list()

    def search_entries(self, query):
        return self._entries.find_by_site(query)

    def export_csv(self, filepath):
        """Export decrypted passwords to CSV. File persistence."""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Site", "Username", "Password", "Created At"])
            for e in self._entries.to_list():
                w.writerow([
                    e.entry_id, e.site, e.username,
                    self.decrypt_password(e.encrypted_password),
                    e.created_at,
                ])
        return filepath


# =============================================================================
# SECTION 3 — COLOUR PALETTE & FONTS
# =============================================================================

BG     = "#0d1117"
PANEL  = "#161b22"
BORDER = "#30363d"
ACCENT = "#58a6ff"
GREEN  = "#39d353"
RED    = "#f85149"
YELLOW = "#e3b341"
FG     = "#e6edf3"
FG2    = "#8b949e"

F_MONO   = ("Courier New", 10)
F_MONO_S = ("Courier New",  9)
F_SANS   = ("Segoe UI",    10)
F_SANS_S = ("Segoe UI",     9)
F_HEAD   = ("Courier New", 18, "bold")


# =============================================================================
# SECTION 4 — LOGIN SCREEN
# =============================================================================

class LoginScreen(tk.Tk):
    """Login/setup screen — shown on every launch."""

    def __init__(self):
        super().__init__()
        self.title("SecureVault — Login")
        self.geometry("460x340")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._vault = VaultCore()
        self._build()

    def _build(self):
        tk.Frame(self, bg=ACCENT, height=4).pack(fill="x")

        hdr = tk.Frame(self, bg=PANEL, height=76)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔐  SecureVault",
                 font=F_HEAD, fg=ACCENT, bg=PANEL).pack(pady=16)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        body = tk.Frame(self, bg=BG, padx=55, pady=26)
        body.pack(fill="both", expand=True)

        is_new = not self._vault.is_setup()
        self._is_new = is_new

        tk.Label(body,
                 text="Create Master Password" if is_new else "Unlock Your Vault",
                 font=("Segoe UI", 12, "bold"), fg=FG, bg=BG).pack(anchor="w")
        tk.Label(body,
                 text=("Choose a strong password (min 6 chars)."
                       if is_new else "Enter your master password to continue."),
                 font=F_SANS_S, fg=FG2, bg=BG).pack(anchor="w", pady=(2, 14))

        tk.Label(body, text="Master Password", font=F_SANS_S,
                 fg=FG2, bg=BG).pack(anchor="w")
        self._v_pw = tk.StringVar()
        pw_e = self._entry(body, self._v_pw, show="•")
        pw_e.pack(fill="x", ipady=7, pady=(3, 0))
        pw_e.focus()

        self._v_cf = tk.StringVar()
        self._cf_frame = tk.Frame(body, bg=BG)
        self._cf_frame.pack(fill="x", pady=(10, 0))
        if is_new:
            tk.Label(self._cf_frame, text="Confirm Password",
                     font=F_SANS_S, fg=FG2, bg=BG).pack(anchor="w")
            self._entry(self._cf_frame, self._v_cf, show="•").pack(
                fill="x", ipady=7, pady=(3, 0))

        self._v_err = tk.StringVar()
        tk.Label(body, textvariable=self._v_err, font=F_SANS_S,
                 fg=RED, bg=BG).pack(anchor="w", pady=(6, 0))

        tk.Button(body,
                  text="Create Vault" if is_new else "Unlock",
                  font=("Segoe UI", 10, "bold"),
                  bg=ACCENT, fg=BG, relief="flat", cursor="hand2",
                  padx=20, pady=8, activebackground=ACCENT,
                  command=self._submit).pack(fill="x", pady=(10, 0))

        self.bind("<Return>", lambda _: self._submit())

    def _entry(self, parent, var, show=None):
        kw = dict(textvariable=var, bg="#21262d", fg=FG,
                  insertbackground=ACCENT, relief="flat", font=F_SANS,
                  highlightthickness=1, highlightcolor=ACCENT,
                  highlightbackground=BORDER)
        if show:
            kw["show"] = show
        return tk.Entry(parent, **kw)

    def _submit(self):
        pw = self._v_pw.get().strip()
        if not pw:
            self._v_err.set("Password cannot be empty.")
            return
        if self._is_new:
            if len(pw) < 6:
                self._v_err.set("Must be at least 6 characters.")
                return
            if pw != self._v_cf.get():
                self._v_err.set("Passwords do not match.")
                return
            try:
                self._vault.setup_master(pw)
                self._vault.authenticate(pw)
            except Exception as e:
                self._v_err.set(str(e))
                return
        else:
            if not self._vault.authenticate(pw):
                self._v_err.set("Incorrect password.")
                return
        self._vault.load_entries()
        self.withdraw()
        VaultApp(self._vault, self).mainloop()


# =============================================================================
# SECTION 5 — MAIN VAULT APP
# =============================================================================

class VaultApp(tk.Toplevel):
    """Main vault window — shown after authentication."""

    def __init__(self, vault, login_root):
        super().__init__()
        self.title("SecureVault — Password Manager")
        self.geometry("980x680")
        self.minsize(820, 500)
        self.configure(bg=BG)
        self._vault      = vault
        self._login_root = login_root
        self._build_styles()
        self._build_ui()
        self._refresh_table()
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ── Styles ────────────────────────────────────────────────────────────────

    def _build_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("V.Treeview",
                    background=PANEL, foreground=FG,
                    fieldbackground=PANEL, rowheight=28,
                    font=F_MONO_S, borderwidth=0)
        s.configure("V.Treeview.Heading",
                    background="#21262d", foreground=FG2,
                    font=(F_SANS_S[0], F_SANS_S[1], "bold"), relief="flat")
        s.map("V.Treeview",
              background=[("selected", "#1f2f4d")],
              foreground=[("selected", FG)])
        s.configure("D.Vertical.TScrollbar",
                    troughcolor=PANEL, background=BORDER,
                    arrowcolor=FG2, bordercolor=PANEL, relief="flat")

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._mk_header()
        self._mk_form()
        self._mk_toolbar()
        self._mk_table()
        self._mk_status()

    def _mk_header(self):
        tk.Frame(self, bg=ACCENT, height=3).pack(fill="x")
        hdr = tk.Frame(self, bg=PANEL, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🔐  SecureVault",
                 font=F_HEAD, fg=ACCENT, bg=PANEL).pack(side="left", padx=18, pady=8)
        tk.Label(hdr, text="Password Manager  ·  ST5062CEM",
                 font=F_SANS_S, fg=FG2, bg=PANEL).pack(side="left")

        tk.Button(hdr, text="🔒 Lock & Exit", font=F_SANS_S,
                  bg=RED, fg=FG, relief="flat", cursor="hand2",
                  padx=12, pady=5, activebackground=RED,
                  command=self._lock).pack(side="right", padx=14, pady=8)
        tk.Button(hdr, text="↓ Export CSV", font=F_SANS_S,
                  bg=BORDER, fg=FG2, relief="flat", cursor="hand2",
                  padx=12, pady=5, activebackground="#3d444d",
                  command=self._export).pack(side="right", padx=(0, 6), pady=8)

        self._v_clock = tk.StringVar()
        tk.Label(hdr, textvariable=self._v_clock,
                 font=F_MONO_S, fg=FG2, bg=PANEL).pack(side="right", padx=14)
        self._tick_clock()
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _mk_form(self):
        f = tk.Frame(self, bg=PANEL, padx=18, pady=12)
        f.pack(fill="x")
        tk.Label(f, text="ADD NEW ENTRY",
                 font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL).grid(row=0, column=0,
                                           columnspan=9, sticky="w", pady=(0, 7))

        def lbl(t):
            return tk.Label(f, text=t, font=F_SANS_S, fg=FG2, bg=PANEL)

        def ent(v, w=18, show=None):
            kw = dict(textvariable=v, width=w, bg="#21262d", fg=FG,
                      insertbackground=ACCENT, relief="flat", font=F_SANS,
                      highlightthickness=1, highlightcolor=ACCENT,
                      highlightbackground=BORDER)
            if show:
                kw["show"] = show
            return tk.Entry(f, **kw)

        self._v_site = tk.StringVar()
        self._v_user = tk.StringVar()
        self._v_pass = tk.StringVar()
        self._v_show = tk.BooleanVar(value=False)

        lbl("Site / App").grid(row=1, column=0, sticky="w")
        ent(self._v_site, 20).grid(row=1, column=1, padx=(5, 18), ipady=5)

        lbl("Username / Email").grid(row=1, column=2, sticky="w")
        ent(self._v_user, 22).grid(row=1, column=3, padx=(5, 18), ipady=5)

        lbl("Password").grid(row=1, column=4, sticky="w")
        self._pw_ent = ent(self._v_pass, 18, show="•")
        self._pw_ent.grid(row=1, column=5, padx=(5, 8), ipady=5)

        tk.Checkbutton(f, text="Show", variable=self._v_show,
                       bg=PANEL, fg=FG2, selectcolor="#21262d",
                       activebackground=PANEL, font=F_SANS_S,
                       highlightthickness=0, cursor="hand2",
                       command=lambda: self._pw_ent.config(
                           show="" if self._v_show.get() else "•"
                       )).grid(row=1, column=6, padx=(0, 10))

        tk.Button(f, text="⚙ Generate", font=F_SANS_S,
                  bg=BORDER, fg=FG2, relief="flat", cursor="hand2",
                  padx=10, pady=6, activebackground="#3d444d",
                  command=self._generate).grid(row=1, column=7, padx=(0, 8))

        tk.Button(f, text="+ Add Entry",
                  font=("Segoe UI", 10, "bold"),
                  bg=ACCENT, fg=BG, relief="flat", cursor="hand2",
                  padx=14, pady=6, activebackground=ACCENT,
                  command=self._add).grid(row=1, column=8)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _mk_toolbar(self):
        tb = tk.Frame(self, bg=BG, padx=18, pady=9)
        tb.pack(fill="x")

        tk.Label(tb, text="🔍", font=F_SANS_S, fg=FG2, bg=BG).pack(side="left")
        self._v_search = tk.StringVar()
        self._v_search.trace_add("write", lambda *_: self._search())
        tk.Entry(tb, textvariable=self._v_search, width=28,
                 bg="#21262d", fg=FG, insertbackground=ACCENT,
                 relief="flat", font=F_SANS,
                 highlightthickness=1, highlightcolor=ACCENT,
                 highlightbackground=BORDER).pack(side="left", padx=(5, 18), ipady=5)

        for txt, cmd, bg_, fg_ in [
            ("👁  Show/Hide Password", self._show_pw, BORDER, FG2),
            ("📋  Copy Password",      self._copy_pw, BORDER, FG2),
            ("🗑  Delete Entry",       self._delete,  "#2d1515", RED),
        ]:
            tk.Button(tb, text=txt, font=F_SANS_S,
                      bg=bg_, fg=fg_, relief="flat", cursor="hand2",
                      padx=10, pady=5, activebackground="#3d444d",
                      command=cmd).pack(side="left", padx=(0, 6))

        self._v_count = tk.StringVar(value="")
        tk.Label(tb, textvariable=self._v_count,
                 font=F_SANS_S, fg=FG2, bg=BG).pack(side="right")

    def _mk_table(self):
        tf = tk.Frame(self, bg=BG, padx=18, pady=0)
        tf.pack(fill="both", expand=True)

        cols = ("ID", "Site", "Username", "Password", "Created")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  style="V.Treeview", selectmode="browse")
        for col, w in zip(cols, [45, 180, 210, 230, 160]):
            self._tree.heading(col, text=col,
                               command=lambda c=col: self._sort(c))
            self._tree.column(col, width=w, anchor="w",
                              stretch=(col == "Username"))

        sb = ttk.Scrollbar(tf, orient="vertical",
                           command=self._tree.yview,
                           style="D.Vertical.TScrollbar")
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._tree.tag_configure("even", background=PANEL)
        self._tree.tag_configure("odd",  background="#0f1620")

    def _mk_status(self):
        sb = tk.Frame(self, bg=PANEL, height=28)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        tk.Frame(sb, bg=ACCENT, width=4).pack(side="left", fill="y")
        self._v_status = tk.StringVar(value="Vault unlocked. Ready.")
        tk.Label(sb, textvariable=self._v_status, font=F_SANS_S,
                 fg=FG2, bg=PANEL, anchor="w").pack(side="left", padx=10)

    # ── Table helpers ─────────────────────────────────────────────────────────

    def _refresh_table(self, entries=None):
        for r in self._tree.get_children():
            self._tree.delete(r)
        if entries is None:
            entries = self._vault.get_all_entries()
        for i, e in enumerate(entries):
            self._tree.insert("", "end", iid=str(e.entry_id),
                              values=(e.entry_id, e.site, e.username,
                                      "••••••••••", e.created_at),
                              tags=("even" if i % 2 == 0 else "odd",))
        n = len(entries)
        self._v_count.set(f"{n} entr{'y' if n == 1 else 'ies'}")

    def _sort(self, col):
        rows = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
        try:
            rows.sort(key=lambda t: int(t[0]))
        except ValueError:
            rows.sort(key=lambda t: t[0].lower())
        for i, (_, k) in enumerate(rows):
            self._tree.move(k, "", i)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _add(self):
        site = self._v_site.get().strip()
        user = self._v_user.get().strip()
        pw   = self._v_pass.get()
        if not all([site, user, pw]):
            messagebox.showerror("Missing Fields",
                                 "Site, username and password are all required.",
                                 parent=self)
            return
        entry = self._vault.add_entry(site, user, pw)
        n     = len(self._tree.get_children())
        self._tree.insert("", "end", iid=str(entry.entry_id),
                          values=(entry.entry_id, entry.site,
                                  entry.username, "••••••••••",
                                  entry.created_at),
                          tags=("even" if n % 2 == 0 else "odd",))
        self._v_site.set(""); self._v_user.set(""); self._v_pass.set("")
        self._v_count.set(f"{n+1} entries")
        self._status(f"Entry added — {site}")

    def _delete(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Delete", "Select an entry first.", parent=self)
            return
        iid  = sel[0]
        site = self._tree.set(iid, "Site")
        if messagebox.askyesno("Delete", f"Delete entry for '{site}'?",
                               parent=self):
            self._vault.delete_entry(int(iid))
            self._tree.delete(iid)
            n = len(self._tree.get_children())
            self._v_count.set(f"{n} entr{'y' if n == 1 else 'ies'}")
            self._status(f"Deleted — {site}")

    def _show_pw(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Show Password",
                                "Select an entry first.", parent=self)
            return
        iid     = sel[0]
        entries = self._vault.get_all_entries()
        entry   = next((e for e in entries if e.entry_id == int(iid)), None)
        if not entry:
            return
        current = self._tree.set(iid, "Password")
        if current == "••••••••••":
            plain = self._vault.decrypt_password(entry.encrypted_password)
            self._tree.set(iid, "Password", plain)
            self._status(f"Password visible for {entry.site}")
        else:
            self._tree.set(iid, "Password", "••••••••••")
            self._status("Password hidden.")

    def _copy_pw(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Copy", "Select an entry first.", parent=self)
            return
        iid     = sel[0]
        entries = self._vault.get_all_entries()
        entry   = next((e for e in entries if e.entry_id == int(iid)), None)
        if not entry:
            return
        plain = self._vault.decrypt_password(entry.encrypted_password)
        self.clipboard_clear()
        self.clipboard_append(plain)
        self.update()
        self._status(f"Password for {entry.site} copied to clipboard!")

    def _generate(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        pw    = "".join(random.SystemRandom().choice(chars) for _ in range(16))
        self._v_pass.set(pw)
        self._pw_ent.config(show="")
        self._v_show.set(True)
        self._status(f"Generated: {pw}")

    def _search(self):
        q = self._v_search.get().strip()
        self._refresh_table(self._vault.search_entries(q) if q else None)

    def _export(self):
        if not self._vault.get_all_entries():
            messagebox.showinfo("Export", "No entries to export.", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".csv",
            filetypes=[("CSV file", "*.csv"), ("All files", "*.*")],
            title="Export vault to CSV"
        )
        if path:
            self._vault.export_csv(path)
            self._status(f"Exported → {path}")

    def _lock(self):
        self._vault.lock()
        self.destroy()
        self._login_root.deiconify()

    def _close(self):
        self._vault.lock()
        self._login_root.destroy()

    def _status(self, msg):
        self._v_status.set(msg)

    def _tick_clock(self):
        self._v_clock.set(datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    app = LoginScreen()
    app.mainloop()


if __name__ == "__main__":
    main()
