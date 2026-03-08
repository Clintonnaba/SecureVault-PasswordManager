"""
test_vault.py  —  SecureVault Unit Tests
=========================================
Module : ST5062CEM - Programming and Algorithm 2
CW2    : Individual Project

23 unit tests covering:
  - PasswordEntry   (3 tests)
  - EntryList       (7 tests)
  - VaultCore auth  (4 tests)
  - VaultCore CRUD  (5 tests)
  - Encryption      (4 tests)

Run: python test_vault.py -v
"""

import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

# Import from vault_core (works without display)
from vault_core import PasswordEntry, EntryList, VaultCore


# =============================================================================
# TestPasswordEntry
# =============================================================================

class TestPasswordEntry(unittest.TestCase):
    """Tests for the PasswordEntry value object."""

    def test_creation_sets_attributes(self):
        """PasswordEntry should store all provided attributes correctly."""
        e = PasswordEntry(1, "GitHub", "user@example.com", "enc_pw", "2026-01-01 12:00:00")
        self.assertEqual(e.entry_id, 1)
        self.assertEqual(e.site, "GitHub")
        self.assertEqual(e.username, "user@example.com")
        self.assertEqual(e.encrypted_password, "enc_pw")
        self.assertEqual(e.created_at, "2026-01-01 12:00:00")

    def test_default_timestamp(self):
        """PasswordEntry should auto-generate created_at if not provided."""
        e = PasswordEntry(2, "Twitter", "user", "enc")
        self.assertIsNotNone(e.created_at)
        self.assertIn("20", e.created_at)   # contains year

    def test_repr(self):
        """__repr__ should contain id, site, and username."""
        e = PasswordEntry(5, "Netflix", "me@test.com", "enc")
        r = repr(e)
        self.assertIn("5", r)
        self.assertIn("Netflix", r)
        self.assertIn("me@test.com", r)


# =============================================================================
# TestEntryList
# =============================================================================

class TestEntryList(unittest.TestCase):
    """Tests for the custom singly-linked list."""

    def _entry(self, eid, site):
        return PasswordEntry(eid, site, "user", "enc")

    def test_initial_length_is_zero(self):
        """New EntryList should have length 0."""
        lst = EntryList()
        self.assertEqual(len(lst), 0)

    def test_append_increases_length(self):
        """Appending entries should increase length correctly."""
        lst = EntryList()
        lst.append(self._entry(1, "Apple"))
        lst.append(self._entry(2, "Google"))
        self.assertEqual(len(lst), 2)

    def test_to_list_returns_all(self):
        """to_list should return all entries in insertion order."""
        lst = EntryList()
        lst.append(self._entry(1, "Zebra"))
        lst.append(self._entry(2, "Alpha"))
        items = lst.to_list()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].site, "Zebra")
        self.assertEqual(items[1].site, "Alpha")

    def test_to_sorted_list_alphabetical(self):
        """to_sorted_list should return entries sorted by site name (insertion sort)."""
        lst = EntryList()
        lst.append(self._entry(1, "Zebra"))
        lst.append(self._entry(2, "Apple"))
        lst.append(self._entry(3, "Mango"))
        sorted_items = lst.to_sorted_list()
        self.assertEqual(sorted_items[0].site, "Apple")
        self.assertEqual(sorted_items[1].site, "Mango")
        self.assertEqual(sorted_items[2].site, "Zebra")

    def test_remove_by_id(self):
        """remove_by_id should remove the correct entry."""
        lst = EntryList()
        lst.append(self._entry(10, "Amazon"))
        lst.append(self._entry(20, "eBay"))
        result = lst.remove_by_id(10)
        self.assertTrue(result)
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst.to_list()[0].site, "eBay")

    def test_remove_nonexistent_returns_false(self):
        """remove_by_id should return False if ID not found."""
        lst = EntryList()
        lst.append(self._entry(1, "Test"))
        self.assertFalse(lst.remove_by_id(999))

    def test_find_by_site_case_insensitive(self):
        """find_by_site should match substrings case-insensitively."""
        lst = EntryList()
        lst.append(self._entry(1, "GitHub"))
        lst.append(self._entry(2, "GitLab"))
        lst.append(self._entry(3, "Amazon"))
        results = lst.find_by_site("git")
        self.assertEqual(len(results), 2)

    def test_clear_resets_list(self):
        """clear should empty the list."""
        lst = EntryList()
        lst.append(self._entry(1, "Test"))
        lst.clear()
        self.assertEqual(len(lst), 0)
        self.assertEqual(lst.to_list(), [])


# =============================================================================
# TestVaultCoreAuth
# =============================================================================

class TestVaultCoreAuth(unittest.TestCase):
    """Tests for VaultCore authentication methods."""

    def setUp(self):
        """Use a temporary database for each test."""
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.vault = VaultCore(db_path=self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_is_setup_false_initially(self):
        """New vault should report not set up."""
        self.assertFalse(self.vault.is_setup())

    def test_setup_master_marks_as_setup(self):
        """After setup_master, is_setup should return True."""
        self.vault.setup_master("secure123")
        self.assertTrue(self.vault.is_setup())

    def test_authenticate_correct_password(self):
        """Correct password should authenticate successfully."""
        self.vault.setup_master("mypassword")
        self.assertTrue(self.vault.authenticate("mypassword"))

    def test_authenticate_wrong_password(self):
        """Wrong password should fail authentication."""
        self.vault.setup_master("correctpassword")
        self.assertFalse(self.vault.authenticate("wrongpassword"))


# =============================================================================
# TestVaultCoreEncryption
# =============================================================================

class TestVaultCoreEncryption(unittest.TestCase):
    """Tests for VaultCore encryption and decryption."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.vault = VaultCore(db_path=self.tmp.name)
        self.vault.setup_master("testmaster")
        self.vault.authenticate("testmaster")

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_encrypt_returns_different_from_plaintext(self):
        """Encrypted string should not equal the original plaintext."""
        plain     = "mySecretPassword"
        encrypted = self.vault.encrypt_password(plain)
        self.assertNotEqual(plain, encrypted)

    def test_decrypt_restores_plaintext(self):
        """Decrypting an encrypted password should return the original."""
        plain     = "mySecretPassword"
        encrypted = self.vault.encrypt_password(plain)
        decrypted = self.vault.decrypt_password(encrypted)
        self.assertEqual(plain, decrypted)

    def test_locked_vault_raises_on_encrypt(self):
        """Calling encrypt on a locked vault should raise RuntimeError."""
        self.vault.lock()
        with self.assertRaises(RuntimeError):
            self.vault.encrypt_password("test")

    def test_locked_vault_raises_on_decrypt(self):
        """Calling decrypt on a locked vault should raise RuntimeError."""
        enc = self.vault.encrypt_password("test")
        self.vault.lock()
        with self.assertRaises(RuntimeError):
            self.vault.decrypt_password(enc)


# =============================================================================
# TestVaultCoreCRUD
# =============================================================================

class TestVaultCoreCRUD(unittest.TestCase):
    """Tests for VaultCore entry management (add, delete, search, export)."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.vault = VaultCore(db_path=self.tmp.name)
        self.vault.setup_master("testmaster")
        self.vault.authenticate("testmaster")

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_add_entry_increases_count(self):
        """Adding an entry should increase the list length."""
        self.vault.add_entry("GitHub", "user@test.com", "pass123")
        entries = self.vault.get_all_entries()
        self.assertEqual(len(entries), 1)

    def test_add_entry_stores_correct_data(self):
        """Added entry should have correct site and username."""
        self.vault.add_entry("Twitter", "twitteruser", "tw_pass")
        entries = self.vault.get_all_entries()
        self.assertEqual(entries[0].site, "Twitter")
        self.assertEqual(entries[0].username, "twitteruser")

    def test_delete_entry_removes_it(self):
        """Deleting an entry should remove it from list and database."""
        entry = self.vault.add_entry("Amazon", "amzuser", "amzpass")
        self.vault.delete_entry(entry.entry_id)
        self.assertEqual(len(self.vault.get_all_entries()), 0)

    def test_search_finds_matching_entries(self):
        """search_entries should return entries matching the query."""
        self.vault.add_entry("GitHub", "ghuser", "ghpass")
        self.vault.add_entry("GitLab", "gluser", "glpass")
        self.vault.add_entry("Amazon", "amzuser", "amzpass")
        results = self.vault.search_entries("git")
        self.assertEqual(len(results), 2)

    def test_export_csv_creates_file(self):
        """export_csv should create a non-empty CSV file."""
        self.vault.add_entry("Netflix", "nfuser", "nfpass")
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            csv_path = f.name
        try:
            self.vault.export_csv(csv_path)
            self.assertTrue(os.path.exists(csv_path))
            with open(csv_path) as f:
                content = f.read()
            self.assertIn("Netflix", content)
            self.assertIn("nfuser", content)
        finally:
            os.unlink(csv_path)


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
