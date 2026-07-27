"""Hashing and fingerprinting utilities."""
from __future__ import annotations

import hashlib
import struct


def sha256_hex(data: str | bytes) -> str:
    """Return SHA256 hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    return hashlib.sha256(data).hexdigest()


def fingerprint(value: str, length: int = 16) -> str:
    """Return a short fingerprint of a value."""
    return sha256_hex(value)[:length]


def content_hash(content: str) -> str:
    """Hash content for deduplication."""
    return sha256_hex(content)


def favicon_hash(content: bytes) -> int:
    """Compute MMH3 favicon hash (compatible with Shodan).

    Uses a simple MurmurHash3-32 implementation to avoid external deps.
    """
    import base64

    encoded = base64.encodebytes(content).decode("ascii")

    # MurmurHash3 32-bit implementation
    seed = 0
    data = encoded.encode("utf-8")
    length = len(data)
    nblocks = length // 4
    h1 = seed
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    mask = 0xFFFFFFFF

    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & mask
        k1 = ((k1 << 15) | (k1 >> 17)) & mask
        k1 = (k1 * c2) & mask
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & mask
        h1 = (h1 * 5 + 0xE6546B64) & mask

    tail_idx = nblocks * 4
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= data[tail_idx + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_idx + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_idx]
        k1 = (k1 * c1) & mask
        k1 = ((k1 << 15) | (k1 >> 17)) & mask
        k1 = (k1 * c2) & mask
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & mask
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & mask
    h1 ^= h1 >> 16

    # Convert to signed 32-bit int (Shodan convention)
    if h1 >= 0x80000000:
        h1 -= 0x100000000

    return h1


def redact(value: str, show_chars: int = 4) -> str:
    """Redact sensitive values, showing only first and last N chars."""
    clean = str(value or "").strip()
    if len(clean) <= show_chars * 2 + 3:
        return clean
    return f"{clean[:show_chars]}...{clean[-show_chars:]}"
