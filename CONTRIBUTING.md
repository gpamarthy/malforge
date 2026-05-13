# Contributing

Thanks for considering a contribution.

## Useful contributions

1. **New output formats** under `templates/`. Current formats: msbuild, hollow, ps1. Plausible additions: COFF, BOF, MSIX, regsvr32 sct, hta.
2. **Evasion stubs** wired into the existing `--amsi` / `--etw` plumbing. Add the Jinja variable in `emit.py` and the injection point in each affected template.
3. **Shellcode source modules** beyond the msfvenom wrapper (e.g. compiled stagers, donut output).
4. **Sandbox-test scenarios** in `tests/` that exercise template + evasion combinations. Tests must run inside `make test-sandbox`; do not add tests that execute payloads on the host.

## Dev setup

```sh
git clone https://github.com/gpamarthy/malforge
cd malforge
pip install -e .[dev]

# All payload generation and tests run in the sandbox container:
make build-sandbox
make test-sandbox     # 202 tests
```

## Code style

- Python 3.10+. `ruff check .` and `mypy malforge/` must pass.
- Four-space indent. Type-annotate public functions in `forge.py`, `emit.py`, `shellcode.py`.
- No emojis. Plain prose in commits, comments, and PR descriptions.
- Conventional commits: `feat(msbuild):`, `fix(shellcode):`, `chore:`, `docs:`, `ci:`.

## Template + evasion contract

Every template under `templates/` that wants to support evasion must:

1. Include `{{ amsi_imports }}` at the import/using level.
2. Include `{{ etw_block }}` at the start of the main execution body.

`emit.py:render()` populates both variables when `--amsi` / `--etw` are set, empty strings otherwise.
