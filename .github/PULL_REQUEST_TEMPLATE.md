<!-- Keep PRs reviewable in one sitting. Multiple small PRs beat one big one. -->

## What this changes

<!-- One or two sentences. -->

## Why

<!-- The motivation. If this is from an issue, link it. -->

## Test plan

- [ ] `make test-sandbox` passes (202+ tests in container)
- [ ] `ruff check .` and `mypy malforge/` clean
- [ ] New template renders with and without `--amsi --etw`, no unsubstituted Jinja
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Authorization

- [ ] Any tests or fixtures added do not execute generated payloads on the host
- [ ] Any sample shellcode is from authorized testing or public CTF challenges

## Notes for reviewers

<!-- Anything tricky or up for discussion. -->
