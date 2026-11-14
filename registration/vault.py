"""Encrypted local account and registration-settings vault."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultError(RuntimeError):
    pass


def _normalize_email(value: Any) -> str:
    return str(value or "").strip().casefold()


def _account_key(value: Any) -> str:
    email = _normalize_email(value)
    if not email or "@" not in email:
        return ""
    return hashlib.sha256(email.encode("utf-8")).hexdigest()


class Vault:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
        self._key = self._load_key()
        self._cipher = AESGCM(self._key)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(self.data_dir / "registration-vault.db"),
            check_same_thread=False,
            timeout=30,
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload BLOB NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                email_key TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        self._db.commit()
        self._migrate_account_keys()
        self._secure_database_files()

    def _load_key(self) -> bytes:
        configured = str(os.environ.get("GROK2API_REGISTRATION_VAULT_KEY") or "").strip()
        if configured:
            try:
                key = base64.b64decode(configured, validate=True)
            except Exception as exc:
                raise VaultError("注册账号库密钥不是有效 Base64") from exc
            if len(key) != 32:
                raise VaultError("注册账号库密钥必须解码为 32 字节")
            return key
        key_path = self.data_dir / "registration-vault.key"
        if key_path.is_file():
            raw = key_path.read_bytes()
            if len(raw) != 32:
                raise VaultError("注册账号库密钥文件损坏")
            return raw
        key = os.urandom(32)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
            os.fsync(fd)
        finally:
            os.close(fd)
        return key

    def _secure_database_files(self) -> None:
        for path in self.data_dir.glob("registration-vault.db*"):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def _encrypt(self, payload: dict[str, Any]) -> bytes:
        nonce = os.urandom(12)
        plaintext = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return nonce + self._cipher.encrypt(nonce, plaintext, None)

    def _decrypt(self, blob: bytes) -> dict[str, Any]:
        if len(blob) <= 12:
            raise VaultError("加密记录已损坏")
        nonce, ciphertext = blob[:12], blob[12:]
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, None)
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise VaultError("注册账号库无法解密，请检查密钥是否被替换") from exc
        if not isinstance(payload, dict):
            raise VaultError("注册账号库记录格式无效")
        return payload

    def _migrate_account_keys(self) -> None:
        rows = self._db.execute(
            "SELECT email_key, payload, created_at, updated_at FROM accounts"
        ).fetchall()
        migrated = 0
        with self._lock:
            for old_key, blob, created_at, updated_at in rows:
                if len(str(old_key)) == 64 and "@" not in str(old_key):
                    continue
                record = self._decrypt(bytes(blob))
                target_key = _account_key(record.get("email") or old_key)
                if not target_key:
                    raise VaultError("注册账号库包含无法迁移的邮箱索引")
                target = self._db.execute(
                    "SELECT payload, created_at, updated_at FROM accounts WHERE email_key = ?",
                    (target_key,),
                ).fetchone()
                if target is None:
                    self._db.execute(
                        "UPDATE accounts SET email_key = ? WHERE email_key = ?",
                        (target_key, old_key),
                    )
                else:
                    if float(updated_at or 0) > float(target[2] or 0):
                        self._db.execute(
                            """
                            UPDATE accounts
                            SET payload = ?, created_at = ?, updated_at = ?
                            WHERE email_key = ?
                            """,
                            (
                                blob,
                                min(float(created_at or 0), float(target[1] or 0)),
                                updated_at,
                                target_key,
                            ),
                        )
                    self._db.execute(
                        "DELETE FROM accounts WHERE email_key = ?",
                        (old_key,),
                    )
                migrated += 1
            if migrated:
                self._db.commit()

    def _get_account_by_key(self, key: str, include_secrets: bool = True) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM accounts WHERE email_key = ?",
                (str(key),),
            ).fetchone()
        if row is None:
            return None
        record = self._decrypt(bytes(row[0]))
        if include_secrets:
            return record
        return {
            "email": record.get("email", ""),
            "hasPassword": bool(record.get("password")),
            "hasSso": bool(record.get("sso")),
            "source": record.get("source", ""),
            "createdAt": record.get("createdAt"),
            "updatedAt": record.get("updatedAt"),
        }

    def get_settings(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT payload FROM settings WHERE id = 1").fetchone()
        return None if row is None else self._decrypt(bytes(row[0]))

    def save_settings(self, value: dict[str, Any]) -> None:
        blob = self._encrypt(value)
        now = time.time()
        with self._lock:
            self._db.execute(
                """
                INSERT INTO settings(id, payload, updated_at) VALUES(1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
                """,
                (blob, now),
            )
            self._db.commit()
        self._secure_database_files()

    def upsert_account(
        self,
        email: str,
        password: str = "",
        sso: str = "",
        source: str = "registration",
    ) -> dict[str, Any]:
        email = str(email or "").strip()
        key = _account_key(email)
        if not key:
            raise VaultError("账号缺少有效邮箱")
        now = time.time()
        with self._lock:
            existing = self._get_account_by_key(key)
            record = existing or {
                "email": email,
                "password": "",
                "sso": "",
                "source": source,
                "createdAt": now,
            }
            if email:
                record["email"] = email
            if password:
                record["password"] = str(password)
            if sso:
                record["sso"] = str(sso).removeprefix("sso=").strip()
            record["source"] = str(source or record.get("source") or "registration")
            record["updatedAt"] = now
            self._db.execute(
                """
                INSERT INTO accounts(email_key, payload, created_at, updated_at) VALUES(?, ?, ?, ?)
                ON CONFLICT(email_key) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (key, self._encrypt(record), float(record["createdAt"]), now),
            )
            self._db.commit()
        self._secure_database_files()
        return record

    def get_account(self, email: str, include_secrets: bool = True) -> dict[str, Any] | None:
        key = _account_key(email)
        if not key:
            return None
        return self._get_account_by_key(key, include_secrets=include_secrets)

    def list_accounts(
        self,
        search: str = "",
        limit: int = 2000,
        include_secrets: bool = False,
    ) -> list[dict[str, Any]]:
        needle = str(search or "").strip().casefold()
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM accounts ORDER BY updated_at DESC"
            ).fetchall()
        values: list[dict[str, Any]] = []
        for row in rows:
            record = self._decrypt(bytes(row[0]))
            if needle and needle not in str(record.get("email") or "").casefold():
                continue
            if include_secrets:
                values.append(record)
            else:
                values.append(
                    {
                        "email": record.get("email", ""),
                        "hasPassword": bool(record.get("password")),
                        "hasSso": bool(record.get("sso")),
                        "source": record.get("source", ""),
                        "createdAt": record.get("createdAt"),
                        "updatedAt": record.get("updatedAt"),
                    }
                )
            if len(values) >= max(1, min(int(limit or 2000), 10000)):
                break
        return values

    def select_accounts(self, emails: Iterable[str]) -> tuple[list[dict[str, Any]], int]:
        values: list[dict[str, Any]] = []
        missing = 0
        seen: set[str] = set()
        for email in emails:
            key = _normalize_email(email)
            if not key or key in seen:
                continue
            seen.add(key)
            record = self.get_account(key)
            if record is None:
                missing += 1
                continue
            values.append(record)
        return values, missing

    def delete_accounts(self, emails: Iterable[str]) -> int:
        keys = sorted({_account_key(email) for email in emails if _account_key(email)})
        if not keys:
            return 0
        with self._lock:
            before = self._db.total_changes
            self._db.executemany(
                "DELETE FROM accounts WHERE email_key = ?",
                [(key,) for key in keys],
            )
            self._db.commit()
            return int(self._db.total_changes - before)

    def close(self) -> None:
        with self._lock:
            self._db.close()
