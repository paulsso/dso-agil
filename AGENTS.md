# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

**dso-agil** (DevSecOps Agent In the Loop) is a Python project. As of this writing, the repository is newly initialized with no application code, dependencies, or services.

### Environment

- **Python 3.12** is the system Python available at `/usr/bin/python3`.
- No virtual environment, `pyproject.toml`, or `requirements.txt` exists yet. When dependency files are added, the update script should be updated accordingly.
- The `.gitignore` is configured for Python and covers common tooling (venv, pytest, mypy, ruff, uv, poetry, pdm, pixi, etc.).

### Development workflow

- **No lint, test, or build commands exist yet.** When they are added, document them here.
- When a `pyproject.toml` or `requirements.txt` is introduced, install dependencies with the appropriate tool (`pip install -r requirements.txt`, `uv sync`, `poetry install`, etc.).
- There are no services to start, no database, and no Docker setup at this time.
