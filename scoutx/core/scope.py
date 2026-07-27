"""Scope management — wildcard domains, CIDR ranges, and exclusions.

Every request ScoutX makes passes through the scope gate first.
If it ain't in scope, it ain't getting touched.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml


def _normalize(value: str) -> str:
    """Strip protocol, trailing dots, whitespace."""
    v = value.strip().lower()
    for prefix in ("https://", "http://", "//"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    v = v.split("/")[0]  # remove path
    v = v.split(":")[0]  # remove port
    return v.rstrip(".")


class Scope:
    """Target scope with wildcard domains, CIDR, and exclusions."""

    def __init__(
        self,
        includes: list[str] | None = None,
        excludes: list[str] | None = None,
    ) -> None:
        self.includes: list[str] = includes or []
        self.excludes: list[str] = excludes or []

    def add(self, pattern: str) -> None:
        """Add an include pattern (domain, wildcard, or CIDR)."""
        normalised = pattern.strip()
        if normalised and normalised not in self.includes:
            self.includes.append(normalised)

    def remove(self, pattern: str) -> None:
        """Remove a pattern from includes."""
        normalised = pattern.strip()
        self.includes = [p for p in self.includes if p != normalised]

    def exclude(self, pattern: str) -> None:
        """Add an exclusion pattern."""
        normalised = pattern.strip()
        if normalised and normalised not in self.excludes:
            self.excludes.append(normalised)

    def is_in_scope(self, target: str) -> bool:
        """Check if a target (domain, IP, URL) is within scope."""
        if not self.includes:
            return True  # no scope = everything is in scope

        normalised = _normalize(target)

        # Check exclusions first — excluded always wins
        for pattern in self.excludes:
            if self._matches(normalised, pattern):
                return False

        # Check includes
        for pattern in self.includes:
            if self._matches(normalised, pattern):
                return True

        return False

    def _matches(self, target: str, pattern: str) -> bool:
        """Check if target matches a scope pattern."""
        pattern_clean = pattern.strip().lower()
        target_clean = target.strip().lower()

        # CIDR match
        if "/" in pattern_clean:
            try:
                network = ipaddress.ip_network(pattern_clean, strict=False)
                addr = ipaddress.ip_address(target_clean)
                return addr in network
            except ValueError:
                pass

        # Wildcard domain: *.example.com
        if pattern_clean.startswith("*."):
            root = pattern_clean[2:]
            return target_clean == root or target_clean.endswith(f".{root}")

        # Exact domain match
        if target_clean == pattern_clean:
            return True

        # Also match subdomains of an exact domain include
        if target_clean.endswith(f".{pattern_clean}"):
            return True

        # fnmatch for other glob patterns
        if fnmatch.fnmatch(target_clean, pattern_clean):
            return True

        return False

    def save(self, path: Path) -> None:
        """Persist scope to YAML."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data: dict[str, Any] = {
            "includes": self.includes,
            "excludes": self.excludes,
        }
        path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Scope:
        """Load scope from YAML file."""
        if not path.exists():
            return cls()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
        except Exception:
            return cls()
        return cls(
            includes=data.get("includes", []) or [],
            excludes=data.get("excludes", []) or [],
        )

    @classmethod
    def from_target(cls, target: str) -> Scope:
        """Create scope from a single target domain."""
        normalised = _normalize(target)
        return cls(includes=[f"*.{normalised}", normalised])

    @classmethod
    def from_file(cls, path: Path) -> Scope:
        """Load scope — auto-detect YAML vs plain text."""
        if path.suffix in (".yaml", ".yml"):
            return cls.load(path)
        # Plain text: one target per line
        scope = cls()
        for line in path.read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                if clean.startswith("!") or clean.startswith("-"):
                    scope.exclude(clean.lstrip("!-").strip())
                else:
                    scope.add(clean)
        return scope

    def __repr__(self) -> str:
        return f"Scope(includes={self.includes}, excludes={self.excludes})"
