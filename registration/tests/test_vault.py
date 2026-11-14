from __future__ import annotations

import hashlib
import pathlib
import sqlite3
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vault import Vault  # noqa: E402


def email_key(email: str) -> str:
    return hashlib.sha256(email.strip().casefold().encode("utf-8")).hexdigest()


class VaultAccountIndexTests(unittest.TestCase):
    def test_new_account_index_is_hashed_and_has_no_plaintext_email(self):
        with tempfile.TemporaryDirectory() as data_dir:
            vault = Vault(data_dir)
            try:
                vault.upsert_account(
                    "Person@Example.com",
                    password="secret-password",
                    sso="sso-token",
                )
                with sqlite3.connect(pathlib.Path(data_dir) / "registration-vault.db") as db:
                    keys = [row[0] for row in db.execute("SELECT email_key FROM accounts")]
            finally:
                vault.close()

            self.assertEqual(keys, [email_key("Person@Example.com")])
            self.assertNotIn("Person@Example.com", keys)
            self.assertNotIn("person@example.com", keys)

    def test_legacy_plaintext_indexes_merge_into_hashed_rows(self):
        with tempfile.TemporaryDirectory() as data_dir:
            vault = Vault(data_dir)
            try:
                self._insert_collision_pair(
                    vault,
                    email="newer-legacy@example.com",
                    legacy_updated_at=300,
                    hashed_updated_at=200,
                )
                self._insert_collision_pair(
                    vault,
                    email="newer-hash@example.com",
                    legacy_updated_at=200,
                    hashed_updated_at=300,
                )
            finally:
                vault.close()

            migrated = Vault(data_dir)
            try:
                accounts = migrated.list_accounts(include_secrets=True)
                self.assertEqual(len(accounts), 2)
                by_email = {record["email"].casefold(): record for record in accounts}
                self.assertEqual(
                    by_email["newer-legacy@example.com"]["password"],
                    "legacy-password",
                )
                self.assertEqual(
                    by_email["newer-hash@example.com"]["password"],
                    "hash-password",
                )

                with sqlite3.connect(pathlib.Path(data_dir) / "registration-vault.db") as db:
                    rows = db.execute(
                        "SELECT email_key, created_at, updated_at FROM accounts ORDER BY email_key"
                    ).fetchall()
            finally:
                migrated.close()

            self.assertEqual(len(rows), 2)
            for key, created_at, updated_at in rows:
                self.assertEqual(len(key), 64)
                self.assertRegex(key, r"^[0-9a-f]{64}$")
                self.assertNotIn("@", key)
                self.assertEqual(created_at, 10)
                self.assertIn(updated_at, {200, 300})

    @staticmethod
    def _insert_collision_pair(
        vault: Vault,
        *,
        email: str,
        legacy_updated_at: float,
        hashed_updated_at: float,
    ) -> None:
        hashed_record = {
            "email": email,
            "password": "hash-password",
            "sso": "hash-sso",
            "source": "registration",
            "createdAt": 10,
            "updatedAt": hashed_updated_at,
        }
        legacy_record = {
            "email": email,
            "password": "legacy-password",
            "sso": "legacy-sso",
            "source": "registration",
            "createdAt": 20,
            "updatedAt": legacy_updated_at,
        }
        with vault._lock:
            vault._db.execute(
                """
                INSERT INTO accounts(email_key, payload, created_at, updated_at)
                VALUES(?, ?, ?, ?)
                """,
                (
                    email_key(email),
                    vault._encrypt(hashed_record),
                    10,
                    hashed_updated_at,
                ),
            )
            vault._db.execute(
                """
                INSERT INTO accounts(email_key, payload, created_at, updated_at)
                VALUES(?, ?, ?, ?)
                """,
                (
                    email.upper(),
                    vault._encrypt(legacy_record),
                    20,
                    legacy_updated_at,
                ),
            )
            vault._db.commit()


if __name__ == "__main__":
    unittest.main()
