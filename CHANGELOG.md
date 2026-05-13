# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-13

First public release. Shellcode encryption and payload generator for red-team and OSEP work.

### Added
- `forge` CLI with three output formats: `msbuild` (csproj), `hollow` (process hollowing C# loader), `ps1` (PowerShell stager)
- `--amsi` flag: emits an AMSI bypass patch via Jinja-templated import + early `Execute()` body injection
- `--etw` flag: emits an ETW patching stub for the same hook points
- `shellcode.py`: msfvenom wrapper with WSL-without-DISPLAY early warning
- Per-payload random crypto material (key, IV) regenerated on every invocation
- Sandbox-only build and test targets in `Makefile` (`build-sandbox`, `test-sandbox`)
- 202 unit tests covering template rendering, evasion injection, and shellcode emission
- COMPAT validation in `forge.py` to refuse incompatible flag combinations
- CI: ruff lint, mypy typecheck, pytest
