---
name: linting
description: Run and fix linters for this Python project via pre-commit or individual tools. Use when the user asks to lint, fix lint errors, run ruff/pylint/mypy/markdownlint, or before committing code.
---

# Linting

## When to use

Apply this skill when the user asks to lint code, fix lint/format errors,
run checks before commit, or mentions ruff, pylint, mypy, markdownlint, or
pre-commit.

## Workflow

1. **venv**: Always run all the python packages from `.venv/bin/`

2. **Default**: Run all linters via pre-commit.
   - First run `pre-commit autoupdate` before running the linters.
   - From project root: `pre-commit run --all-files`
   - Install hooks first if needed: `pre-commit install`

3. **Single tool** (only when the user asks for one):
   - Ruff: `ruff check .` then `ruff format .` (or `ruff check --fix`)
   - Pylint: `pylint src/` (or paths given)
   - Mypy: `mypy src/`
   - Markdownlint: as in `.pre-commit-config.yaml` for `*.md`

4. **Fix then verify**:
   - Organize the import with ruff
   - Always use full paths to the ruff executable. Run check first, then format:

    ```bash
    .venv/bin/ruff check . --fix && .venv/bin/ruff format .
    ```

   - After fixing issues, run `pre-commit run --all-files` again.

## Project config

- Linter config lives in `pyproject.toml` (Ruff, Pylint, Mypy). Follow
  `.cursor/rules/project-standards/linting-guidelines.mdc`.
- Pre-commit hooks: `.pre-commit-config.yaml`. Use the project’s venv
  and run from repo root.
