# Security Policy

## Supported versions

HoneyJam is alpha software; security fixes are applied to the latest release on
the `main` branch only.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

- Use GitHub's [private vulnerability reporting](https://github.com/sltcnb/HoneyJam/security/advisories/new)
  ("Report a vulnerability" under the repository's Security tab), or
- Open a minimal public issue asking a maintainer to establish a private
  channel, without disclosing details.

Please include the affected version, reproduction steps and impact. We aim to
acknowledge reports within a few days.

## Handling forensic data safely

HoneyJam parses untrusted third-party registry hives. Treat every input hive as
potentially hostile:

- Run analysis on isolated, non-production systems.
- Mount evidence read-only (the Docker image expects hives under `/data`).
- Do not commit real hives or extracted artifacts that contain sensitive data
  to source control.
