from __future__ import annotations

import asyncio
import logging
from pathlib import Path

logger = logging.getLogger("scoutx.wordlists")

class WordlistManager:
    """Manage wordlists for ScoutX scanning."""

    WORDLIST_DIR = Path.home() / ".scoutx" / "wordlists"
    BUILTIN_DIR = Path(__file__).parent

    # Known wordlist collections with git URLs
    COLLECTIONS = {
        "seclists": "https://github.com/danielmiessler/SecLists.git",
        "assetnote": "https://github.com/assetnote/wordlists.git",
        "fuzzdb": "https://github.com/fuzzdb-project/fuzzdb.git",
    }

    def get_wordlist(self, category: str, config_override: str = "") -> Path:
        """Get wordlist path. Priority: config override > custom download > builtin."""
        if config_override and Path(config_override).exists():
            return Path(config_override)

        # Example categories: common-dirs, common-subdomains, common-params
        builtin = self.BUILTIN_DIR / f"{category}.txt"
        if builtin.exists():
            return builtin

        raise FileNotFoundError(f"Wordlist for category '{category}' not found.")

    async def download_collection(self, name: str, url: str = "") -> bool:
        """Download a wordlist collection via git clone."""
        if not url:
            url = self.COLLECTIONS.get(name)
            if not url:
                logger.error(f"Unknown collection: {name}")
                return False

        dest = self.WORDLIST_DIR / name
        if dest.exists():
            logger.info(f"Collection {name} already exists at {dest}")
            return True

        logger.info(f"Cloning {url} into {dest}...")
        self.WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", url, str(dest),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()

        if proc.returncode == 0:
            logger.info(f"Successfully downloaded {name}")
            return True
        else:
            logger.error(f"Failed to download {name}")
            return False

    def list_installed(self) -> list[dict[str, str]]:
        """List installed wordlist collections."""
        if not self.WORDLIST_DIR.exists():
            return []

        res = []
        for p in self.WORDLIST_DIR.iterdir():
            if p.is_dir():
                res.append({"name": p.name, "path": str(p), "type": "downloaded"})
        return res

    def list_builtin(self) -> list[dict[str, str]]:
        """List built-in wordlists."""
        res = []
        for p in self.BUILTIN_DIR.glob("*.txt"):
            res.append({"name": p.stem, "path": str(p), "type": "builtin"})
        return res
