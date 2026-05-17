"""Local storage using SQLite.

Stores identities, sigchains, keys, messages, and content.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from nodetide.core.crypto import KeyPair
from nodetide.core.identity import Identity, Sigchain


SCHEMA_VERSION = 1

SCHEMA = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- Local identities (ones we control)
CREATE TABLE IF NOT EXISTS local_identities (
    identity_hash TEXT PRIMARY KEY,
    signing_key TEXT NOT NULL,
    encryption_key TEXT NOT NULL,
    is_default INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- All known sigchains (local and remote)
CREATE TABLE IF NOT EXISTS sigchains (
    identity_hash TEXT PRIMARY KEY,
    sigchain_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Trust assertions
CREATE TABLE IF NOT EXISTS trust_assertions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asserter_identity TEXT NOT NULL,
    subject_identity TEXT NOT NULL,
    claimed_name TEXT,
    verification TEXT,
    confidence REAL NOT NULL,
    timestamp INTEGER NOT NULL,
    note TEXT,
    signature TEXT NOT NULL,
    UNIQUE(asserter_identity, subject_identity, timestamp)
);

-- Trust delegations
CREATE TABLE IF NOT EXISTS trust_delegations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_identity TEXT NOT NULL,
    to_identity TEXT NOT NULL,
    weight REAL NOT NULL,
    depth_limit INTEGER,
    timestamp INTEGER NOT NULL,
    UNIQUE(from_identity, to_identity)
);

-- Messages (received and sent)
CREATE TABLE IF NOT EXISTS messages (
    message_hash TEXT PRIMARY KEY,
    bundle_json TEXT NOT NULL,
    sender_identity TEXT NOT NULL,
    recipient_identity TEXT,
    message_type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    received_at INTEGER,
    read_at INTEGER,
    status TEXT DEFAULT 'pending'
);

-- Content chunks
CREATE TABLE IF NOT EXISTS content_chunks (
    chunk_hash TEXT PRIMARY KEY,
    manifest_hash TEXT,
    chunk_index INTEGER,
    data BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Content manifests
CREATE TABLE IF NOT EXISTS content_manifests (
    manifest_hash TEXT PRIMARY KEY,
    manifest_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    total_size INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

-- Relay warnings (unreliable relays)
CREATE TABLE IF NOT EXISTS relay_warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    relay_node TEXT NOT NULL,
    reporter_identity TEXT NOT NULL,
    issue TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence TEXT,
    timestamp INTEGER NOT NULL,
    signature TEXT NOT NULL
);

-- Routing hints
CREATE TABLE IF NOT EXISTS routing_hints (
    identity_hash TEXT NOT NULL,
    node_identity TEXT NOT NULL,
    cla_type TEXT NOT NULL,
    address TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    confidence REAL DEFAULT 1.0,
    PRIMARY KEY (identity_hash, node_identity)
);

-- Groups
CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    group_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_identity);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_identity);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status);
CREATE INDEX IF NOT EXISTS idx_trust_assertions_subject ON trust_assertions(subject_identity);
CREATE INDEX IF NOT EXISTS idx_routing_hints_identity ON routing_hints(identity_hash);
"""


@dataclass
class Storage:
    """SQLite-based local storage."""

    db_path: Path
    _conn: sqlite3.Connection | None = None

    @classmethod
    def open(cls, db_path: Path | str) -> Storage:
        """Open or create a storage database."""
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        storage = cls(db_path=db_path)
        storage._connect()
        storage._init_schema()
        return storage

    @classmethod
    def memory(cls) -> Storage:
        """Create an in-memory storage (for testing)."""
        storage = cls(db_path=Path(":memory:"))
        storage._conn = sqlite3.connect(":memory:", check_same_thread=False)
        storage._conn.row_factory = sqlite3.Row
        storage._init_schema()
        return storage

    def _connect(self) -> None:
        """Connect to the database."""
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def _init_schema(self) -> None:
        """Initialize the database schema."""
        with self.transaction() as cur:
            cur.executescript(SCHEMA)

            # Check/set schema version
            cur.execute("SELECT version FROM schema_version LIMIT 1")
            row = cur.fetchone()
            if row is None:
                cur.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """Context manager for a database transaction."""
        if self._conn is None:
            self._connect()

        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # Identity operations

    def save_local_identity(self, identity: Identity, is_default: bool = False) -> None:
        """Save a local identity (one we control)."""
        if not identity.local_keypair:
            raise ValueError("Cannot save: not a local identity")

        import time

        with self.transaction() as cur:
            # If setting as default, clear other defaults
            if is_default:
                cur.execute("UPDATE local_identities SET is_default = 0")

            cur.execute(
                """
                INSERT OR REPLACE INTO local_identities
                (identity_hash, signing_key, encryption_key, is_default, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    identity.identity_hash,
                    identity.local_keypair.signing_key.to_hex(),
                    identity.local_keypair.encryption_key.to_hex(),
                    1 if is_default else 0,
                    int(time.time()),
                ),
            )

            # Also save the sigchain
            self._save_sigchain_internal(cur, identity.sigchain)

    def _save_sigchain_internal(self, cur: sqlite3.Cursor, sigchain: Sigchain) -> None:
        """Save a sigchain (internal, within transaction)."""
        import time

        cur.execute(
            """
            INSERT OR REPLACE INTO sigchains (identity_hash, sigchain_json, updated_at)
            VALUES (?, ?, ?)
            """,
            (sigchain.identity_hash, sigchain.to_json(), int(time.time())),
        )

    def save_sigchain(self, sigchain: Sigchain) -> None:
        """Save a sigchain (local or remote)."""
        with self.transaction() as cur:
            self._save_sigchain_internal(cur, sigchain)

    def get_local_identity(self, identity_hash: str) -> Identity | None:
        """Get a local identity by hash."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT signing_key, encryption_key FROM local_identities WHERE identity_hash = ?",
                (identity_hash,),
            )
            key_row = cur.fetchone()
            if not key_row:
                return None

            cur.execute(
                "SELECT sigchain_json FROM sigchains WHERE identity_hash = ?",
                (identity_hash,),
            )
            chain_row = cur.fetchone()
            if not chain_row:
                return None

            keypair = KeyPair.from_dict({
                "signing_key": key_row["signing_key"],
                "encryption_key": key_row["encryption_key"],
            })
            sigchain = Sigchain.from_json(chain_row["sigchain_json"])

            return Identity(sigchain=sigchain, local_keypair=keypair)

    def get_default_identity(self) -> Identity | None:
        """Get the default local identity."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT identity_hash FROM local_identities WHERE is_default = 1 LIMIT 1"
            )
            row = cur.fetchone()
            if not row:
                # Fall back to first identity
                cur.execute("SELECT identity_hash FROM local_identities LIMIT 1")
                row = cur.fetchone()

            if not row:
                return None

            return self.get_local_identity(row["identity_hash"])

    def list_local_identities(self) -> list[str]:
        """List all local identity hashes."""
        with self.transaction() as cur:
            cur.execute("SELECT identity_hash FROM local_identities ORDER BY created_at")
            return [row["identity_hash"] for row in cur.fetchall()]

    def list_all_sigchains(self) -> list[str]:
        """List all sigchain identity hashes (local and remote)."""
        with self.transaction() as cur:
            cur.execute("SELECT identity_hash FROM sigchains ORDER BY updated_at DESC")
            return [row["identity_hash"] for row in cur.fetchall()]

    def get_sigchain(self, identity_hash: str) -> Sigchain | None:
        """Get a sigchain by identity hash."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT sigchain_json FROM sigchains WHERE identity_hash = ?",
                (identity_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return Sigchain.from_json(row["sigchain_json"])

    # Message operations

    def save_message(
        self,
        message_hash: str,
        bundle_json: str,
        sender_identity: str,
        recipient_identity: str | None,
        message_type: str,
        created_at: int,
        received_at: int | None = None,
        status: str = "pending",
    ) -> None:
        """Save a message."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO messages
                (message_hash, bundle_json, sender_identity, recipient_identity,
                 message_type, created_at, received_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_hash,
                    bundle_json,
                    sender_identity,
                    recipient_identity,
                    message_type,
                    created_at,
                    received_at,
                    status,
                ),
            )

    def get_message(self, message_hash: str) -> dict | None:
        """Get a message by hash."""
        with self.transaction() as cur:
            cur.execute("SELECT * FROM messages WHERE message_hash = ?", (message_hash,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_messages(
        self,
        identity_hash: str | None = None,
        sender_identity: str | None = None,
        message_type: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """List messages, optionally filtered."""
        query = "SELECT * FROM messages WHERE 1=1"
        params = []

        if identity_hash:
            query += " AND (sender_identity = ? OR recipient_identity = ?)"
            params.extend([identity_hash, identity_hash])

        if sender_identity:
            query += " AND sender_identity = ?"
            params.append(sender_identity)

        if message_type:
            query += " AND message_type = ?"
            params.append(message_type)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.transaction() as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]

    def mark_message_read(self, message_hash: str) -> None:
        """Mark a message as read."""
        import time

        with self.transaction() as cur:
            cur.execute(
                "UPDATE messages SET read_at = ?, status = 'read' WHERE message_hash = ?",
                (int(time.time()), message_hash),
            )

    # Content operations

    def save_content_manifest(
        self,
        manifest_hash: str,
        manifest_json: str,
        content_hash: str,
        total_size: int,
    ) -> None:
        """Save a content manifest."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO content_manifests
                (manifest_hash, manifest_json, content_hash, total_size, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (manifest_hash, manifest_json, content_hash, total_size, int(time.time())),
            )

    def save_content_chunk(
        self,
        chunk_hash: str,
        data: bytes,
        manifest_hash: str | None = None,
        chunk_index: int | None = None,
    ) -> None:
        """Save a content chunk."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO content_chunks
                (chunk_hash, manifest_hash, chunk_index, data, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (chunk_hash, manifest_hash, chunk_index, data, int(time.time())),
            )

    def get_content_chunk(self, chunk_hash: str) -> bytes | None:
        """Get a content chunk by hash."""
        with self.transaction() as cur:
            cur.execute("SELECT data FROM content_chunks WHERE chunk_hash = ?", (chunk_hash,))
            row = cur.fetchone()
            return row["data"] if row else None

    # Routing hints

    def save_routing_hint(
        self,
        identity_hash: str,
        node_identity: str,
        cla_type: str,
        address: str,
        confidence: float = 1.0,
    ) -> None:
        """Save a routing hint."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO routing_hints
                (identity_hash, node_identity, cla_type, address, last_seen, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (identity_hash, node_identity, cla_type, address, int(time.time()), confidence),
            )

    def get_routing_hints(self, identity_hash: str) -> list[dict]:
        """Get routing hints for an identity."""
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT * FROM routing_hints
                WHERE identity_hash = ?
                ORDER BY last_seen DESC, confidence DESC
                """,
                (identity_hash,),
            )
            return [dict(row) for row in cur.fetchall()]

    # Trust operations

    def save_trust_assertion(
        self,
        asserter_identity: str,
        subject_identity: str,
        confidence: float,
        timestamp: int,
        signature: str,
        claimed_name: str | None = None,
        verification: str | None = None,
        note: str | None = None,
    ) -> None:
        """Save a trust assertion."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO trust_assertions
                (asserter_identity, subject_identity, claimed_name, verification,
                 confidence, timestamp, note, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asserter_identity,
                    subject_identity,
                    claimed_name,
                    verification,
                    confidence,
                    timestamp,
                    note,
                    signature,
                ),
            )

    def get_trust_assertions(self, subject_identity: str) -> list[dict]:
        """Get trust assertions about an identity."""
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT * FROM trust_assertions
                WHERE subject_identity = ?
                ORDER BY timestamp DESC
                """,
                (subject_identity,),
            )
            return [dict(row) for row in cur.fetchall()]

    def save_trust_delegation(
        self,
        from_identity: str,
        to_identity: str,
        weight: float,
        timestamp: int,
        depth_limit: int | None = None,
    ) -> None:
        """Save a trust delegation."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO trust_delegations
                (from_identity, to_identity, weight, depth_limit, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (from_identity, to_identity, weight, depth_limit, timestamp),
            )

    def get_trust_delegations(self, from_identity: str) -> list[dict]:
        """Get trust delegations from an identity."""
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT * FROM trust_delegations
                WHERE from_identity = ?
                ORDER BY weight DESC
                """,
                (from_identity,),
            )
            return [dict(row) for row in cur.fetchall()]

    def set_default_identity(self, identity_hash: str) -> bool:
        """Set an existing local identity as the default.

        Returns True if successful, False if identity not found.
        """
        with self.transaction() as cur:
            # Check if identity exists
            cur.execute(
                "SELECT identity_hash FROM local_identities WHERE identity_hash = ?",
                (identity_hash,),
            )
            if not cur.fetchone():
                return False

            # Clear all defaults, then set the new one
            cur.execute("UPDATE local_identities SET is_default = 0")
            cur.execute(
                "UPDATE local_identities SET is_default = 1 WHERE identity_hash = ?",
                (identity_hash,),
            )
            return True
