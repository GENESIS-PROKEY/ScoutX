"""Async data access layer — all database operations go through here.

Uses SQLAlchemy 2.0 async with aiosqlite. Every method is async because
we're not savages who block the event loop.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from scoutx.database.models import Base, Finding, Host, Module, Scan

logger = logging.getLogger("scoutx.database")


class Repository:
    """Async database access layer using aiosqlite + SQLAlchemy."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._engine = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    async def initialize(self) -> None:
        """Create engine and ensure all tables exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite+aiosqlite:///{self._db_path}"
        self._engine = create_async_engine(url, echo=False)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.debug("Database initialised at %s", self._db_path)

    async def close(self) -> None:
        """Close the database engine."""
        if self._engine:
            await self._engine.dispose()

    def _session(self) -> AsyncSession:
        if not self._session_factory:
            raise RuntimeError("Repository not initialised — call initialize() first")
        return self._session_factory()

    # ── Scan operations ────────────────────────────────────────────────

    async def create_scan(self, scan_id: str, target: str, profile: str, config: dict[str, Any]) -> Scan:
        async with self._session() as session:
            scan = Scan(
                id=scan_id,
                target=target,
                profile=profile,
                status="running",
                started_at=datetime.now(timezone.utc),
                config_snapshot=config,
            )
            session.add(scan)
            await session.commit()
            return scan

    async def update_scan(self, scan_id: str, **kwargs: Any) -> None:
        async with self._session() as session:
            await session.execute(update(Scan).where(Scan.id == scan_id).values(**kwargs))
            await session.commit()

    async def get_scan(self, scan_id: str) -> Scan | None:
        async with self._session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            return result.scalar_one_or_none()

    async def get_scans_for_target(self, target: str) -> list[Scan]:
        async with self._session() as session:
            result = await session.execute(
                select(Scan).where(Scan.target == target).order_by(Scan.started_at.desc())
            )
            return list(result.scalars().all())

    async def get_latest_scan(self, target: str) -> Scan | None:
        async with self._session() as session:
            result = await session.execute(
                select(Scan).where(Scan.target == target).order_by(Scan.started_at.desc()).limit(1)
            )
            return result.scalar_one_or_none()

    # ── Host operations ────────────────────────────────────────────────

    async def add_host(self, scan_id: str, hostname: str, **kwargs: Any) -> Host:
        async with self._session() as session:
            host = Host(scan_id=scan_id, hostname=hostname, **kwargs)
            session.add(host)
            await session.commit()
            return host

    async def add_hosts_bulk(self, scan_id: str, hosts: list[dict[str, Any]]) -> int:
        async with self._session() as session:
            objects = [Host(scan_id=scan_id, **h) for h in hosts]
            session.add_all(objects)
            await session.commit()
            return len(objects)

    async def get_hosts(self, scan_id: str, alive_only: bool = False) -> list[Host]:
        async with self._session() as session:
            query = select(Host).where(Host.scan_id == scan_id)
            if alive_only:
                query = query.where(Host.alive == True)  # noqa: E712
            result = await session.execute(query)
            return list(result.scalars().all())

    # ── Finding operations ─────────────────────────────────────────────

    async def add_finding(self, scan_id: str, plugin_name: str, finding_type: str, **kwargs: Any) -> Finding:
        async with self._session() as session:
            finding = Finding(scan_id=scan_id, plugin_name=plugin_name, finding_type=finding_type, **kwargs)
            session.add(finding)
            await session.commit()
            return finding

    async def add_findings_bulk(self, scan_id: str, findings: list[dict[str, Any]]) -> int:
        async with self._session() as session:
            objects = [Finding(scan_id=scan_id, **f) for f in findings]
            session.add_all(objects)
            await session.commit()
            return len(objects)

    async def get_findings(
        self,
        scan_id: str,
        finding_type: str | None = None,
        severity: str | None = None,
    ) -> list[Finding]:
        async with self._session() as session:
            query = select(Finding).where(Finding.scan_id == scan_id)
            if finding_type:
                query = query.where(Finding.finding_type == finding_type)
            if severity:
                query = query.where(Finding.severity == severity)
            result = await session.execute(query)
            return list(result.scalars().all())

    # ── Module tracking ────────────────────────────────────────────────

    async def track_module(self, scan_id: str, name: str, status: str, **kwargs: Any) -> Module:
        async with self._session() as session:
            module = Module(
                scan_id=scan_id,
                name=name,
                status=status,
                started_at=datetime.now(timezone.utc),
                **kwargs,
            )
            session.add(module)
            await session.commit()
            return module

    async def update_module(self, scan_id: str, name: str, **kwargs: Any) -> None:
        async with self._session() as session:
            await session.execute(
                update(Module).where(Module.scan_id == scan_id, Module.name == name).values(**kwargs)
            )
            await session.commit()

    async def get_modules(self, scan_id: str) -> list[Module]:
        async with self._session() as session:
            result = await session.execute(select(Module).where(Module.scan_id == scan_id))
            return list(result.scalars().all())

    # ── Diff support ───────────────────────────────────────────────────

    async def diff_scans(self, scan_id_a: str, scan_id_b: str) -> dict[str, Any]:
        """Compare two scans and return differences."""
        hosts_a = {h.hostname for h in await self.get_hosts(scan_id_a)}
        hosts_b = {h.hostname for h in await self.get_hosts(scan_id_b)}

        findings_a = await self.get_findings(scan_id_a)
        findings_b = await self.get_findings(scan_id_b)

        finding_keys_a = {(f.finding_type, f.title, f.target_url) for f in findings_a}
        finding_keys_b = {(f.finding_type, f.title, f.target_url) for f in findings_b}

        return {
            "new_hosts": sorted(hosts_b - hosts_a),
            "removed_hosts": sorted(hosts_a - hosts_b),
            "unchanged_hosts": len(hosts_a & hosts_b),
            "new_findings": len(finding_keys_b - finding_keys_a),
            "resolved_findings": len(finding_keys_a - finding_keys_b),
            "total_hosts_a": len(hosts_a),
            "total_hosts_b": len(hosts_b),
        }
