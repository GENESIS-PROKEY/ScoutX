import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from scoutx.core.config import ScoutXConfig

app = FastAPI(title="ScoutX Dashboard")

config = ScoutXConfig()
RESULTS_DIR = config.output_dir

# We will mount static files later down in the file after defining API routes to ensure API routes match first if needed,
# though FastAPI routes order matters.
# Actually, let's just mount static files at the end.

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/api/scans")
def list_scans() -> dict[str, list[str]]:
    if not RESULTS_DIR.exists():
        return {"scans": []}
    scans = [d.name for d in RESULTS_DIR.iterdir() if d.is_dir() and (d / "scan_state.json").exists()]
    return {"scans": scans}

def read_json_safe(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

@app.get("/api/scans/{target}")
def get_scan(target: str) -> dict[str, Any]:
    target_dir = RESULTS_DIR / target
    if not target_dir.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    
    state = read_json_safe(target_dir / "scan_state.json")
    
    # Collect summary metrics
    results = {}
    for child in target_dir.iterdir():
        if child.is_dir():
            json_file = child / f"{child.name}.json"
            if json_file.exists():
                results[child.name] = read_json_safe(json_file)
    
    return {
        "target": target,
        "state": state,
        "results": results
    }

@app.get("/api/scans/{target}/intelligence")
def get_intelligence(target: str) -> dict[str, Any]:
    target_dir = RESULTS_DIR / target
    data = read_json_safe(target_dir / "intelligence" / "intelligence.json")
    return data

@app.get("/api/scans/{target}/subdomains")
def get_subdomains(target: str) -> dict[str, Any]:
    target_dir = RESULTS_DIR / target
    data = read_json_safe(target_dir / "subdomains" / "subdomains.json")
    return data

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

