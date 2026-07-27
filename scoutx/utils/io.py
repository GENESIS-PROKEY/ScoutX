"""File I/O utilities — atomic writes, JSON helpers, path management."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def ensure_dir(path: Path) -> Path:
    """Create directory tree and return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Crash-safe write via temp file + rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(content, encoding=encoding)
        tmp.replace(path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def write_json(path: Path, data: Any, indent: int = 2) -> None:
    """Write formatted JSON to a file (atomic)."""
    content = json.dumps(data, indent=indent, default=str, ensure_ascii=False)
    atomic_write_text(path, content)


def write_jsonl(path: Path, items: list[dict[str, Any]]) -> None:
    """Write JSON Lines to a file."""
    lines = [json.dumps(item, default=str, ensure_ascii=False) for item in items]
    atomic_write_text(path, "\n".join(lines) + "\n" if lines else "")


def read_json(path: Path, default: Any = None) -> Any:
    """Read JSON from a file with graceful fallback."""
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read JSON Lines from a file."""
    if not path.exists():
        return []
    items: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                items.append(obj)
        except json.JSONDecodeError:
            continue
    return items


def read_lines(path: Path) -> list[str]:
    """Read non-empty, non-comment lines from a file."""
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def safe_filename(url: str, max_length: int = 200) -> str:
    """Convert a URL to a filesystem-safe filename."""
    # Strip scheme
    name = re.sub(r"^https?://", "", url)
    # Replace unsafe chars
    name = re.sub(r"[/\\?&=:@#%\[\]{}|^~`<>\"']+", "_", name)
    # Remove consecutive underscores
    name = re.sub(r"_+", "_", name).strip("_")
    # Truncate
    if len(name) > max_length:
        name = name[:max_length]
    return name or "unnamed"
