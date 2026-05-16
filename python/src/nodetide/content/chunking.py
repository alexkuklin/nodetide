"""Content chunking for large files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from nodetide.core.crypto import hash_bytes, hash_hex

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64KB default


@dataclass
class Chunk:
    """A single chunk of content."""

    index: int
    data: bytes
    chunk_hash: str

    @classmethod
    def create(cls, index: int, data: bytes) -> Chunk:
        """Create a chunk with computed hash."""
        return cls(
            index=index,
            data=data,
            chunk_hash=hash_hex(data),
        )

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "hash": self.chunk_hash,
            "size": len(self.data),
        }

    def verify(self) -> bool:
        """Verify chunk integrity."""
        return hash_hex(self.data) == self.chunk_hash


def chunk_bytes(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[Chunk]:
    """Split bytes into chunks."""
    offset = 0
    index = 0

    while offset < len(data):
        chunk_data = data[offset : offset + chunk_size]
        yield Chunk.create(index, chunk_data)
        offset += chunk_size
        index += 1


def chunk_file(path: Path | str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[Chunk]:
    """Split a file into chunks."""
    path = Path(path)
    index = 0

    with open(path, "rb") as f:
        while True:
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break
            yield Chunk.create(index, chunk_data)
            index += 1


def reassemble_chunks(chunks: list[Chunk]) -> bytes:
    """Reassemble chunks into complete data.

    Chunks must be sorted by index.
    """
    # Sort by index
    sorted_chunks = sorted(chunks, key=lambda c: c.index)

    # Verify contiguous
    for i, chunk in enumerate(sorted_chunks):
        if chunk.index != i:
            raise ValueError(f"Missing chunk at index {i}")

    # Verify integrity
    for chunk in sorted_chunks:
        if not chunk.verify():
            raise ValueError(f"Chunk {chunk.index} failed integrity check")

    return b"".join(c.data for c in sorted_chunks)


def reassemble_to_file(
    chunks: list[Chunk],
    output_path: Path | str,
) -> None:
    """Reassemble chunks directly to a file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = reassemble_chunks(chunks)

    with open(output_path, "wb") as f:
        f.write(data)


@dataclass
class ChunkRequest:
    """Request for specific chunks."""

    manifest_hash: str
    chunk_indices: list[int]

    def to_dict(self) -> dict:
        return {
            "manifest_hash": self.manifest_hash,
            "chunk_indices": self.chunk_indices,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ChunkRequest:
        return cls(
            manifest_hash=data["manifest_hash"],
            chunk_indices=data["chunk_indices"],
        )


@dataclass
class ChunkAvailability:
    """Information about which chunks a node has."""

    manifest_hash: str
    available_chunks: list[int]
    total_chunks: int

    def to_dict(self) -> dict:
        return {
            "manifest_hash": self.manifest_hash,
            "available_chunks": self.available_chunks,
            "total_chunks": self.total_chunks,
        }

    @property
    def is_complete(self) -> bool:
        return len(self.available_chunks) == self.total_chunks

    @property
    def missing_chunks(self) -> list[int]:
        all_indices = set(range(self.total_chunks))
        available = set(self.available_chunks)
        return sorted(all_indices - available)
