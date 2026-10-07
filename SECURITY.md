# Security Policy

## Reporting a vulnerability

If you find a security issue in osintMagic, please report it privately rather
than opening a public issue:

- Use GitHub's **"Report a vulnerability"** under the repository's **Security** tab
  (private security advisories), or
- Contact the maintainer via GitHub ([@REFFIX-X](https://github.com/REFFIX-X)).

Please include: a description, steps to reproduce, and the impact. Do not include
real API keys, credentials, or personal data of third parties.

We aim to acknowledge reports within a few days.

## Scope & what this tool does

osintMagic is a **read-only OSINT tool** that queries publicly available
information. By design it does **not**:

- bypass authentication or access protected resources
- brute-force or test credentials
- exploit vulnerabilities
- access private profiles or paid data without the user's own API key

Reports most relevant here are things like: **SSRF or request-forgery paths**,
**injection via user input**, **local secrets exposure** (e.g. API keys leaking
into logs, exports, or error messages), or a **supply-chain issue** in a
dependency.

## Handling of secrets

- API keys are optional and stored **locally** in `~/.osintmagic/keys.json`
  (outside the repository, git-ignored).
- Keys are only ever sent to the service they belong to; they are never written
  into reports, exports, or logs by this project.
- Never commit keys. `.env`, `*.env`, and `.streamlit/secrets.toml` are ignored.

## Lawful use

This software is provided for lawful, authorized, and educational use only. See
[DISCLAIMER.md](DISCLAIMER.md). Misuse is the sole responsibility of the user.
