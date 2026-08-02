import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from scoutx.wordlists import WordlistManager

wordlist_app = typer.Typer(help="Manage wordlists.", no_args_is_help=True)
console = Console()
manager = WordlistManager()

@wordlist_app.command("list")
def list_wordlists() -> None:
    """List available wordlists."""
    table = Table(title="Available Wordlists")
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Path", style="green")
    
    builtins = manager.list_builtin()
    for w in builtins:
        table.add_row(w["name"], w["type"], w["path"])
        
    installed = manager.list_installed()
    for w in installed:
        table.add_row(w["name"], w["type"], w["path"])
        
    console.print(table)

@wordlist_app.command("download")
def download_wordlist(name: str = typer.Argument(..., help="Collection name or git URL")) -> None:
    """Download a wordlist collection."""
    url = ""
    if name.startswith("http"):
        url = name
        name = name.split("/")[-1].replace(".git", "")
        
    console.print(f"Downloading {name}...")
    success = asyncio.run(manager.download_collection(name, url))
    
    if success:
        console.print(f"[green]Successfully downloaded {name}[/green]")
    else:
        console.print(f"[red]Failed to download {name}[/red]")
        raise typer.Exit(1)

@wordlist_app.command("info")
def wordlist_info(name: str = typer.Argument(..., help="Wordlist name")) -> None:
    """Show details about a wordlist."""
    builtins = manager.list_builtin()
    for w in builtins:
        if w["name"] == name:
            console.print(f"[bold]Name:[/bold] {w['name']}")
            console.print(f"[bold]Type:[/bold] {w['type']}")
            console.print(f"[bold]Path:[/bold] {w['path']}")
            path = Path(w["path"])
            if path.exists():
                lines = path.read_text(encoding="utf-8").splitlines()
                console.print(f"[bold]Lines:[/bold] {len(lines)}")
            return
            
    installed = manager.list_installed()
    for w in installed:
        if w["name"] == name:
            console.print(f"[bold]Name:[/bold] {w['name']}")
            console.print(f"[bold]Type:[/bold] {w['type']}")
            console.print(f"[bold]Path:[/bold] {w['path']}")
            return
            
    console.print(f"[red]Wordlist '{name}' not found.[/red]")
