import pytest
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock

from scoutx.core.config import ScoutXConfig
from scoutx.core.engine import ScanEngine
from scoutx.core.events import EventBus
from scoutx.core.scope import Scope
from scoutx.database.repository import Repository
from scoutx.plugins.manager import PluginManager


@pytest.fixture
def test_config(tmp_path: Path):
    return ScoutXConfig(
        config_path=None,
        overrides={
            "output_dir": str(tmp_path / "results"),
            "database_path": str(tmp_path / "scoutx.db"),
            "scan_profile": "safe",
        }
    )


@pytest.mark.asyncio
async def test_minimal_scan_pipeline(tmp_path: Path, test_config: ScoutXConfig):
    """Test a minimal scan pipeline with mocked network responses."""
    target = "example.com"
    scope = Scope.from_target(target)
    
    db_path = Path(test_config.database_path)
    db = Repository(db_path)
    await db.initialize()
    
    event_bus = EventBus()
    plugin_manager = PluginManager(test_config)
    plugin_manager.discover_builtin()
    
    # Mock httpx.AsyncClient.request to simulate network responses
    with patch("httpx.AsyncClient.request") as mock_request:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_request.return_value = mock_response
        
        engine = ScanEngine(
            config=test_config,
            scope=scope,
            plugin_manager=plugin_manager,
            db=db,
            event_bus=event_bus,
        )
        
        result = await engine.run(
            target=target,
            profile="safe",
            output_dir=tmp_path / "results"
        )
        
        # Verify result status
        assert result.status in ("completed", "partial")
        assert result.duration_seconds >= 0
        
        # Verify that output directory was created
        target_dir = tmp_path / "results" / target
        assert target_dir.exists()
        
        # Verify scan state was saved
        state_file = target_dir / "scan_state.json"
        assert state_file.exists()
