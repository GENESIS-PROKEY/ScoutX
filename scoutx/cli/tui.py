from __future__ import annotations
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.columns import Columns
from scoutx.cli.ui import console

class ScanTUI:
    """Live terminal UI for scan progress."""
    
    def __init__(self, target: str, total_plugins: int):
        self.target = target
        self.total_plugins = total_plugins
        self.completed = 0
        self.current_plugin = ""
        self.findings: list[dict] = []  # Recent findings feed
        self.plugin_statuses: dict[str, str] = {}  # plugin_name -> status emoji
        self.stats = {"subdomains": 0, "alive": 0, "findings": 0, "ports": 0}
        self._live: Live | None = None
        self._progress: Progress | None = None
        self._task_id = None
    
    def start(self):
        """Start the live TUI display."""
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            TextColumn("{task.completed}/{task.total} plugins"),
            TimeElapsedColumn(),
            console=console,
        )
        self._task_id = self._progress.add_task(f"Scanning {self.target}", total=self.total_plugins)
        self._live = Live(self._build_display(), console=console, refresh_per_second=4)
        self._live.start()
    
    def update_plugin(self, name: str, status: str):
        """Update a plugin's status: waiting, running, done, failed, skipped."""
        emoji_map = {"waiting": "⏳", "running": "🔄", "done": "✅", "failed": "❌", "skipped": "⏭️"}
        self.plugin_statuses[name] = emoji_map.get(status, "❓")
        if status == "running":
            self.current_plugin = name
        if status in ("done", "failed", "skipped"):
            self.completed += 1
            if self._progress and self._task_id is not None:
                self._progress.update(self._task_id, completed=self.completed)
        if self._live:
            self._live.update(self._build_display())
    
    def add_finding(self, severity: str, title: str, plugin: str):
        """Add a finding to the live feed."""
        colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
        self.findings.append({"severity": severity, "title": title, "plugin": plugin, "color": colors.get(severity, "white")})
        self.stats["findings"] += 1
        if len(self.findings) > 8:  # Keep last 8
            self.findings = self.findings[-8:]
        if self._live:
            self._live.update(self._build_display())
    
    def update_stats(self, **kwargs):
        """Update stats counters."""
        self.stats.update(kwargs)
        if self._live:
            self._live.update(self._build_display())
    
    def finish(self):
        """Stop the live display."""
        if self._live:
            self._live.stop()
    
    def _build_display(self) -> Panel:
        layout = Layout()
        layout.split_column(
            Layout(name="progress", size=3),
            Layout(name="stats", size=3),
            Layout(name="content")
        )
        layout["content"].split_row(
            Layout(name="plugins"),
            Layout(name="findings")
        )
        
        # 1. Progress
        if self._progress:
            layout["progress"].update(Panel(self._progress, border_style="cyan", padding=(0, 2)))
            
        # 2. Stats
        stats_cols = Columns([
            Panel(f"[bold white]{self.stats['subdomains']}[/]", title="Subdomains", border_style="cyan", padding=(0, 2)),
            Panel(f"[bold white]{self.stats['alive']}[/]", title="Alive", border_style="cyan", padding=(0, 2)),
            Panel(f"[bold white]{self.stats['ports']}[/]", title="Ports", border_style="cyan", padding=(0, 2)),
            Panel(f"[bold white]{self.stats['findings']}[/]", title="Findings", border_style="cyan", padding=(0, 2))
        ], expand=True)
        layout["stats"].update(stats_cols)
        
        # 3. Plugins
        plugin_grid = Table.grid(padding=(0, 2))
        plugin_grid.add_column()
        plugin_grid.add_column()
        plugin_grid.add_column()
        plugin_grid.add_column()
        
        items = list(self.plugin_statuses.items())
        for i in range(0, len(items), 4):
            row = []
            for j in range(4):
                if i + j < len(items):
                    name, status = items[i+j]
                    row.append(f"{status} {name}")
                else:
                    row.append("")
            plugin_grid.add_row(*row)
            
        layout["plugins"].update(Panel(plugin_grid, title="Plugin Status", border_style="cyan"))
        
        # 4. Findings
        findings_table = Table.grid(padding=(0, 1))
        findings_table.add_column(style="bold")
        findings_table.add_column()
        findings_table.add_column(style="dim")
        for f in reversed(self.findings):
            findings_table.add_row(f"[{f['color']}]{f['severity'].upper()}[/]", f["title"], f"[{f['plugin']}]")
            
        layout["findings"].update(Panel(findings_table, title="Recent Findings", border_style="cyan"))
        
        return Panel(layout, title="[bold cyan]ScoutX Live Scan[/]", border_style="cyan")
