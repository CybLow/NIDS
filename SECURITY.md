# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest `main` | Yes |
| older releases | Best effort |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, please report security issues by emailing the maintainer directly or using GitHub's [private vulnerability reporting](https://github.com/CybLow/NIDS/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive a response within 48 hours. We will coordinate disclosure once a fix is available.

## Scope

This project processes raw network traffic and runs ML inference. Security-relevant areas include:
- Packet parsing (buffer overflows, malformed input)
- ONNX model loading (untrusted model files)
- gRPC server (authentication, input validation)
- Threat intelligence feed loading (file parsing)
- Configuration file parsing (JSON injection)
