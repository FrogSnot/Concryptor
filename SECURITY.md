# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately using GitHub's
[Private Vulnerability Reporting](https://github.com/FrogSnot/Concryptor/security/advisories/new)
feature. This lets us coordinate a fix and disclosure before the issue becomes public.

Include as much detail as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- Any suggested fix or mitigation, if you have one

We aim to acknowledge reports within **72 hours** and to publish a fix within **14 days**
for critical issues, depending on complexity.

## Scope

Issues of particular interest for a cryptographic tool:

- Incorrect AEAD tag verification or bypass
- Nonce reuse or collision
- Key derivation weaknesses
- Header/AAD authentication gaps
- Path traversal in archive extraction
- Insecure key/password handling or zeroization failures
