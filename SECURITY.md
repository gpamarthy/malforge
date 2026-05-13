# Security policy

## Supported versions

Pre-1.0, only the latest tagged release receives security fixes.

## Reporting a vulnerability

**Do not file public issues for security problems.**

Email a description and reproduction to the maintainer. Expect an acknowledgement within 72 hours and a fix or mitigation plan within 14 days for issues that can be reproduced.

If no response in 14 days, you are free to disclose publicly.

## Scope

In scope:

- Vulnerabilities in malforge itself (RCE in the generator, command injection into msfvenom args, path traversal in output paths)
- Crypto material reuse across invocations (each payload must regenerate its own key/IV)
- Sandbox escape: anything in `make build-sandbox` / `make test-sandbox` that lets the test container affect the host

Out of scope:

- The payloads malforge emits. They are designed for authorized red-team and OSEP coursework. Operators are responsible for use.
- Evasion success or failure against any specific EDR or AV. Detections rotate; we do not track or guarantee bypass rates.
- Vulnerabilities in upstream `msfvenom`, `dotnet`, or `pwsh`. Report to the respective project.

## Use policy

`malforge` is intended for legal, authorized offensive-security work: pentest engagements, red-team operations, OSEP coursework, and CTF challenges. Run the generator and emitted payloads only on systems and networks where you have written authorization to test.

The sandbox Makefile targets exist so contributors can validate changes without ever executing payloads on the host.
