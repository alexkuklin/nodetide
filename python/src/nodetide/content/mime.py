"""MIME-style content handling."""

from __future__ import annotations

import base64
import mimetypes
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ContentDisposition(str, Enum):
    """Content disposition."""

    INLINE = "inline"
    ATTACHMENT = "attachment"


class ContentEncoding(str, Enum):
    """Content encoding."""

    UTF8 = "utf-8"
    BASE64 = "base64"
    BINARY = "binary"


@dataclass
class Content:
    """A single piece of content."""

    content_type: str
    body: bytes | str
    encoding: ContentEncoding = ContentEncoding.UTF8
    disposition: ContentDisposition = ContentDisposition.INLINE
    filename: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        if isinstance(self.body, bytes):
            if self.encoding == ContentEncoding.BASE64:
                body_str = base64.b64encode(self.body).decode("ascii")
            else:
                body_str = self.body.hex()
        else:
            body_str = self.body

        return {
            "content_type": self.content_type,
            "encoding": self.encoding.value,
            "disposition": self.disposition.value,
            "filename": self.filename,
            "body": body_str,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Content:
        """Load from dictionary."""
        encoding = ContentEncoding(data.get("encoding", "utf-8"))
        body_data = data["body"]

        if encoding == ContentEncoding.BASE64:
            body = base64.b64decode(body_data)
        elif encoding == ContentEncoding.BINARY:
            body = bytes.fromhex(body_data)
        else:
            body = body_data

        return cls(
            content_type=data["content_type"],
            body=body,
            encoding=encoding,
            disposition=ContentDisposition(data.get("disposition", "inline")),
            filename=data.get("filename"),
        )

    @classmethod
    def from_text(cls, text: str, content_type: str = "text/plain") -> Content:
        """Create text content."""
        return cls(
            content_type=content_type,
            body=text,
            encoding=ContentEncoding.UTF8,
            disposition=ContentDisposition.INLINE,
        )

    @classmethod
    def from_file(cls, path: Path | str) -> Content:
        """Create content from a file."""
        path = Path(path)

        # Detect MIME type
        mime_type, _ = mimetypes.guess_type(str(path))
        if mime_type is None:
            mime_type = "application/octet-stream"

        # Read file
        with open(path, "rb") as f:
            data = f.read()

        # Determine encoding
        if mime_type.startswith("text/"):
            try:
                text = data.decode("utf-8")
                return cls(
                    content_type=mime_type,
                    body=text,
                    encoding=ContentEncoding.UTF8,
                    disposition=ContentDisposition.ATTACHMENT,
                    filename=path.name,
                )
            except UnicodeDecodeError:
                pass

        return cls(
            content_type=mime_type,
            body=data,
            encoding=ContentEncoding.BASE64,
            disposition=ContentDisposition.ATTACHMENT,
            filename=path.name,
        )

    @property
    def size(self) -> int:
        """Get content size in bytes."""
        if isinstance(self.body, bytes):
            return len(self.body)
        return len(self.body.encode("utf-8"))

    def get_bytes(self) -> bytes:
        """Get body as bytes."""
        if isinstance(self.body, bytes):
            return self.body
        return self.body.encode("utf-8")


class MultipartType(str, Enum):
    """Multipart content types."""

    MIXED = "multipart/mixed"
    ALTERNATIVE = "multipart/alternative"
    RELATED = "multipart/related"


@dataclass
class MultipartContent:
    """Multipart content (message with attachments, etc)."""

    multipart_type: MultipartType
    parts: list[Content] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content_type": self.multipart_type.value,
            "parts": [p.to_dict() for p in self.parts],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MultipartContent:
        """Load from dictionary."""
        return cls(
            multipart_type=MultipartType(data["content_type"]),
            parts=[Content.from_dict(p) for p in data.get("parts", [])],
        )

    def add_part(self, content: Content) -> None:
        """Add a part."""
        self.parts.append(content)

    def add_text(self, text: str, content_type: str = "text/plain") -> None:
        """Add text content."""
        self.add_part(Content.from_text(text, content_type))

    def add_file(self, path: Path | str) -> None:
        """Add file content."""
        self.add_part(Content.from_file(path))

    @property
    def total_size(self) -> int:
        """Get total size of all parts."""
        return sum(p.size for p in self.parts)

    @classmethod
    def mixed(cls) -> MultipartContent:
        """Create a mixed multipart (message + attachments)."""
        return cls(multipart_type=MultipartType.MIXED)

    @classmethod
    def alternative(cls) -> MultipartContent:
        """Create an alternative multipart (same content in different formats)."""
        return cls(multipart_type=MultipartType.ALTERNATIVE)


def create_text_message(text: str) -> dict[str, Any]:
    """Create a simple text message content dict."""
    return Content.from_text(text).to_dict()


def create_message_with_attachment(text: str, file_path: Path | str) -> dict[str, Any]:
    """Create a message with an attachment."""
    mp = MultipartContent.mixed()
    mp.add_text(text)
    mp.add_file(file_path)
    return mp.to_dict()


def create_html_message(html: str, plain_text: str | None = None) -> dict[str, Any]:
    """Create an HTML message with optional plain text alternative."""
    if plain_text:
        mp = MultipartContent.alternative()
        mp.add_text(plain_text)
        mp.add_text(html, "text/html")
        return mp.to_dict()
    else:
        return Content.from_text(html, "text/html").to_dict()
