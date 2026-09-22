# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (main) | ✅ |

## Reporting a vulnerability

Open a **private security advisory** on GitHub
(Security tab → Report a vulnerability) or email the maintainer directly.
Do not open a public issue for security reports.

What to include: affected version/commit, steps to reproduce, and the
impact you see (data access, bypass, leak). You will get an initial
response within 7 days.

## Scope notes

This project assumes a trusted local machine over stdio — whoever holds
`.env` holds the deployment's access level. The `trust`-auth warning in
provisioning must be resolved before any shared deployment. Networked,
multi-user hardening (per-caller auth, TLS) is tracked as roadmap work,
not current protection.
