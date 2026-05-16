"""Content manifests for large content distribution."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nodetide.core.crypto import KeyPair, hash_bytes, hash_hex, hash_json
from nodetide.content.chunking import (
    Chunk,
    chunk_file,
    chunk_bytes,
    DEFAULT_CHUNK_SIZE,
)


@dataclass
class ChunkInfo:
    """Information about a chunk in the manifest."""

    index: int
    chunk_hash: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "hash": self.chunk_hash,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChunkInfo:
        return cls(
            index=data["index"],
            chunk_hash=data["hash"],
            size=data["size"],
        )


@dataclass
class ContentManifest:
    """Manifest for large content split into chunks."""

    content_hash: str  # hash of complete content
    content_type: str
    total_size: int
    chunk_size: int
    chunks: list[ChunkInfo]
    filename: str | None = None
    created_at: int = 0
    expires: int | None = None
    available_from: list[str] = field(default_factory=list)  # node hints
    signature: str = ""

    @property
    def manifest_hash(self) -> str:
        """Hash of this manifest."""
        return hash_json(self.signable_dict())

    @property
    def num_chunks(self) -> int:
        return len(self.chunks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "content_type": self.content_type,
            "total_size": self.total_size,
            "chunk_size": self.chunk_size,
            "chunks": [c.to_dict() for c in self.chunks],
            "filename": self.filename,
            "created_at": self.created_at,
            "expires": self.expires,
            "available_from": self.available_from,
            "signature": self.signature,
        }

    def signable_dict(self) -> dict[str, Any]:
        d = self.to_dict()
        del d["signature"]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContentManifest:
        return cls(
            content_hash=data["content_hash"],
            content_type=data["content_type"],
            total_size=data["total_size"],
            chunk_size=data["chunk_size"],
            chunks=[ChunkInfo.from_dict(c) for c in data["chunks"]],
            filename=data.get("filename"),
            created_at=data.get("created_at", 0),
            expires=data.get("expires"),
            available_from=data.get("available_from", []),
            signature=data.get("signature", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ContentManifest:
        return cls.from_dict(json.loads(json_str))

    def sign(self, keypair: KeyPair) -> None:
        """Sign the manifest."""
        signable = json.dumps(self.signable_dict(), sort_keys=True, separators=(",", ":"))
        self.signature = keypair.sign_hex(signable.encode("utf-8"))

    def get_chunk_hash(self, index: int) -> str | None:
        """Get hash for a specific chunk."""
        for chunk in self.chunks:
            if chunk.index == index:
                return chunk.chunk_hash
        return None

    def verify_chunk(self, chunk: Chunk) -> bool:
        """Verify a chunk against this manifest."""
        expected_hash = self.get_chunk_hash(chunk.index)
        if expected_hash is None:
            return False
        return chunk.chunk_hash == expected_hash

    @classmethod
    def from_file(
        cls,
        path: Path | str,
        keypair: KeyPair,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        content_type: str | None = None,
        expires: int | None = None,
    ) -> tuple[ContentManifest, list[Chunk]]:
        """Create a manifest from a file.

        Returns (manifest, list of chunks).
        """
        import mimetypes

        path = Path(path)

        # Detect content type
        if content_type is None:
            content_type, _ = mimetypes.guess_type(str(path))
            if content_type is None:
                content_type = "application/octet-stream"

        # Read and hash full content
        with open(path, "rb") as f:
            full_data = f.read()

        content_hash = hash_hex(full_data)

        # Create chunks
        chunks = list(chunk_file(path, chunk_size))

        # Build chunk info
        chunk_infos = [
            ChunkInfo(index=c.index, chunk_hash=c.chunk_hash, size=len(c.data))
            for c in chunks
        ]

        manifest = cls(
            content_hash=content_hash,
            content_type=content_type,
            total_size=len(full_data),
            chunk_size=chunk_size,
            chunks=chunk_infos,
            filename=path.name,
            created_at=int(time.time()),
            expires=expires,
        )

        manifest.sign(keypair)

        return manifest, chunks

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        keypair: KeyPair,
        content_type: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        filename: str | None = None,
        expires: int | None = None,
    ) -> tuple[ContentManifest, list[Chunk]]:
        """Create a manifest from bytes.

        Returns (manifest, list of chunks).
        """
        content_hash = hash_hex(data)

        # Create chunks
        chunks = list(chunk_bytes(data, chunk_size))

        # Build chunk info
        chunk_infos = [
            ChunkInfo(index=c.index, chunk_hash=c.chunk_hash, size=len(c.data))
            for c in chunks
        ]

        manifest = cls(
            content_hash=content_hash,
            content_type=content_type,
            total_size=len(data),
            chunk_size=chunk_size,
            chunks=chunk_infos,
            filename=filename,
            created_at=int(time.time()),
            expires=expires,
        )

        manifest.sign(keypair)

        return manifest, chunks


@dataclass
class ContentAnnounce:
    """Announcement that content is available."""

    manifest: ContentManifest
    sender: str  # identity hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "sender": self.sender,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContentAnnounce:
        return cls(
            manifest=ContentManifest.from_dict(data["manifest"]),
            sender=data["sender"],
        )


def should_chunk(content_size: int, threshold: int = DEFAULT_CHUNK_SIZE) -> bool:
    """Determine if content should be chunked based on size."""
    return content_size >= threshold
