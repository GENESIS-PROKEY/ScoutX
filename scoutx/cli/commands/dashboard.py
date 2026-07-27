"""Dashboard CLI command."""
from __future__ import annotations

import typer
import uvicorn

from scoutx.cli.ui import info

dashboard_app = typer.Typer(help="Start the web dashboard.", no_args_is_help=False)

@dashboard_app.callback(invoke_without_command=True)
def main(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
) -> None:
    """Start the ScoutX web dashboard."""
    info(f"Starting ScoutX dashboard on http://{host}:{port}")
    uvicorn.run("scoutx.web.api:app", host=host, port=port, reload=False)

def register(app: typer.Typer) -> None:
    app.add_typer(dashboard_app, name="dashboard")
