"""
vault_core.py  —  SecureVault Password Manager
================================================
Module : ST5062CEM - Programming and Algorithm 2
CW2    : Individual Project

Contains all core logic:
  - PasswordEntry  : value object for a vault entry
  - EntryList      : custom singly-linked list (user-defined data structure)
  - VaultCore      : encryption, authentication, SQLite DB, CSV export
"""

import os
import csv
import sqlite3
import hashlib
import secrets
from datetime import datetime
from cryptography.fernet import Fernet


# =============================================================================
# SECTION 1 — CUSTOM DATA STRUCTURES
# =============================================================================

class PasswordEntry:
    """
    Value object representing a single password vault entry.

    Attributes
    ----------
    entry_id           : int   – unique ID from database
    site               : str   – website or application name
    username           : str   – username or email
    encrypted_password : str   – Fernet-encrypted password string
    created_at         : str   – ISO timestamp of creation
    """

    def __init__(self, entry_id: int, site: str, username: str,
                 encrypted_password: str, created_at: str = None):
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
    User-defined singly-linked list that stores PasswordEntry objects.

    Implements a custom data structure rather than Python's built-in list,
    satisfying the coursework requirement for user-defined structures.

    Complexity
    ----------
    append          : O(n)  — walks to tail each time
    remove_by_id    : O(n)  — linear scan
    find_by_site    : O(n)  — linear scan (case-insensitive substring match)
    to_sorted_list  : O(n²) — insertion sort by site name
    clear           : O(1)
    """

    # ── Internal node ─────────────────────────────────────────────────────────
    class _Node:
        __slots__ = ("data", "next")

        def __init__(self, data: PasswordEntry):
            self.data = data
            self.next = None   # type: ignore[assignment]

    # ── Constructor ───────────────────────────────────────────────────────────
    def __init__(self):
        self._head = None
        self._size = 0

    # ── Public interface ──────────────────────────────────────────────────────

    def append(self, data: PasswordEntry) -> None:
        """Insert a new entry at the tail. O(n)."""
        node = self._Node(data)
        if self._head is None:
            self._head = node
        else:
            cur = self._head
            while cur.next:
                cur = cur.next
            cur.next = node
        self._size += 1

    def remove_by_id(self, entry_id: int) -> bool:
        """
        Remove entry matching entry_id. Returns True if found and removed.
        O(n) linear scan.
        """
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

    def find_by_site(self, query: str) -> list:
        """
        Return all entries whose site name contains query (case-insensitive).
        O(n) traversal.
        """
        results = []
        cur = self._head
        while cur:
            if query.lower() in cur.data.site.lower():
                results.append(cur.data)
            cur = cur.next
        return results

    def to_sorted_list(self) -> list:
        """
        Return all entries as a list sorted alphabetically by site name.
        Uses insertion sort — O(n²) — to satisfy custom algorithm requirement.
        """
        items: list = []
        cur = self._head
        while cur:
            items.append(cur.data)
            cur = cur.next

        # Insertion sort by site name (case-insensitive)
        for i in range(1, len(items)):
            key = items[i]
            j   = i - 1
            while j >= 0 and items[j].site.lower() > key.site.lower():
                items[j + 1] = items[j]
                j -= 1
            items[j + 1] = key

        return items

    def to_list(self) -> list:
        """Return all entries in insertion order."""
        items = []
        cur   = self._head
        while cur:
            items.append(cur.data)
            cur = cur.next
        return items

    def clear(self) -> None:
        """Reset list to empty in O(1)."""
        self._head = None
        self._size = 0

    def __len__(self) -> int:
        return self._size


# =============================================================================
# SECTION 2 — VAULT CORE (Authentication, Encryption, Persistence)
# =============================================================================

class VaultCore:
    """
    Core password manager engine.

    Security design
    ---------------
    - Master password is never stored in plaintext.
      It is hashed with SHA-256 using a random 32-byte salt (PBKDF-style).
    - Each vault entry's password is encrypted with Fernet symmetric encryption.
      The Fernet key is stored in the database, protected by the master password
      authentication gate (only accessible after successful login).
    - SQL queries use parameterised statements only — no string interpolation,
      preventing SQL injection attacks.
    - Passwords are decrypted only on explicit user request, never stored in
      memory in plaintext beyond the moment of display.

    Persistence
    -----------
    - SQLite database  : primary storage (data-at-rest)
    - CSV export       : flat-file persistence on demand
    """

    def __init__(self, db_path: str = "vault.db"):
        self.db_path  = db_path
        self._fernet  = None      # Set only after successful authentication
        self._entries = EntryList()
        self._init_db()

    # ── Database setup ────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create database tables if they do not already exist."""
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

    # ── Authentication ────────────────────────────────────────────────────────

    def is_setup(self) -> bool:
        """Return True if a master password has already been configured."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM master").fetchone()
            return row[0] > 0

    def setup_master(self, master_password: str) -> None:
        """
        Hash the master password with a fresh random salt and store it.
        Generate and store a new Fernet encryption key.
        Raises ValueError if master_password is too short.
        """
        if len(master_password) < 6:
            raise ValueError("Master password must be at least 6 characters.")
        salt          = secrets.token_hex(32)
        password_hash = hashlib.sha256(
            (master_password + salt).encode()
        ).hexdigest()
        fernet_key    = Fernet.generate_key().decode()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM master")
            conn.execute(
                "INSERT INTO master (password_hash, salt, fernet_key) VALUES (?, ?, ?)",
                (password_hash, salt, fernet_key)
            )
            conn.commit()

    def authenticate(self, master_password: str) -> bool:
        """
        Verify master password. If correct, initialise the Fernet cipher.
        Returns True on success, False on failure.
        """
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT password_hash, salt, fernet_key FROM master"
            ).fetchone()
        if not row:
            return False
        stored_hash, salt, fernet_key = row
        computed = hashlib.sha256(
            (master_password + salt).encode()
        ).hexdigest()
        if computed == stored_hash:
            self._fernet = Fernet(fernet_key.encode())
            return True
        return False

    def lock(self) -> None:
        """Clear the in-memory Fernet key (logout)."""
        self._fernet = None
        self._entries.clear()

    # ── Encryption helpers ────────────────────────────────────────────────────

    def encrypt_password(self, plaintext: str) -> str:
        """Encrypt a plaintext password string using Fernet."""
        if not self._fernet:
            raise RuntimeError("Vault is locked. Authenticate first.")
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt_password(self, ciphertext: str) -> str:
        """Decrypt a Fernet-encrypted password back to plaintext."""
        if not self._fernet:
            raise RuntimeError("Vault is locked. Authenticate first.")
        return self._fernet.decrypt(ciphertext.encode()).decode()

    # ── Entry CRUD ────────────────────────────────────────────────────────────

    def add_entry(self, site: str, username: str, password: str) -> PasswordEntry:
        """
        Encrypt password and persist a new entry to the database.
        Also adds to the in-memory linked list.
        """
        encrypted  = self.encrypt_password(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO entries (site, username, encrypted_password, created_at) "
                "VALUES (?, ?, ?, ?)",
                (site, username, encrypted, created_at)
            )
            entry_id = cursor.lastrowid
            conn.commit()
        entry = PasswordEntry(entry_id, site, username, encrypted, created_at)
        self._entries.append(entry)
        return entry

    def delete_entry(self, entry_id: int) -> None:
        """Remove entry from database and in-memory list."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM entries WHERE id = ?", (entry_id,)
            )
            conn.commit()
        self._entries.remove_by_id(entry_id)

    def load_entries(self) -> list:
        """Load all entries from database into the linked list."""
        self._entries.clear()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, site, username, encrypted_password, created_at "
                "FROM entries ORDER BY site"
            ).fetchall()
        for row in rows:
            self._entries.append(PasswordEntry(*row))
        return self._entries.to_list()

    def get_all_entries(self) -> list:
        """Return all entries from the in-memory linked list."""
        return self._entries.to_sorted_list()

    def search_entries(self, query: str) -> list:
        """Search entries by site name substring."""
        return self._entries.find_by_site(query)

    # ── Export ────────────────────────────────────────────────────────────────

    def export_csv(self, filepath: str) -> str:
        """
        Export all vault entries (with decrypted passwords) to a CSV file.
        Returns the filepath on success.
        """
        entries = self._entries.to_list()
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Site", "Username", "Password", "Created At"])
            for e in entries:
                writer.writerow([
                    e.entry_id,
                    e.site,
                    e.username,
                    self.decrypt_password(e.encrypted_password),
                    e.created_at,
                ])
        return filepath
