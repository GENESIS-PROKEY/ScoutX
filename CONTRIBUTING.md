# Contributing to ScoutX

Thanks for wanting to contribute! Here's how to get started.

---

## Development Setup

```bash
# Clone the repo
git clone https://github.com/lo/ScoutX.git
cd ScoutX

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install in dev mode with test deps
pip install -e ".[dev]"

# Run tests
pytest tests/
```

---

## Code Style

- **Python 3.10+** — Use modern type hints, `match` statements where appropriate
- **Async first** — All plugin logic should be async
- **Absolute imports** — `from scoutx.plugins.base import PhantomPlugin`
- **Type hints** — All function signatures should be typed
- **Docstrings** — Google style for public APIs

We use **ruff** for linting:

```bash
ruff check scoutx/
ruff format scoutx/
```

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-scanner`
3. Write your code with tests
4. Run the test suite: `pytest tests/`
5. Run the linter: `ruff check scoutx/`
6. Submit a PR with a clear description

### PR Checklist

- [ ] Tests pass (`pytest tests/`)
- [ ] Linter passes (`ruff check scoutx/`)
- [ ] New features have tests
- [ ] Documentation updated if needed
- [ ] Commit messages are clear

---

## Adding a Plugin

The fastest way to contribute is by adding a new scanner plugin.
See [docs/PLUGINS.md](docs/PLUGINS.md) for the full guide.

Quick version:

1. Create `scoutx/plugins/builtin/my_scanner/`
2. Add `__init__.py` and `plugin.py`
3. Implement the `PhantomPlugin` interface
4. The plugin manager auto-discovers it

---

## Reporting Bugs

Open an issue with:
- ScoutX version (`scoutx --version`)
- Python version
- OS and version
- Steps to reproduce
- Expected vs actual behavior
- `scoutx doctor` output

---

## Feature Requests

Open an issue with:
- Description of the feature
- Use case / motivation
- Any reference implementations

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
