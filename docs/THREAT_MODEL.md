# Threat Model

## Protected boundary

3LOCKBOX protects an upstream execution surface from being reached before IP evidence satisfies the active admission policy.

## Threats addressed

- explicitly denied geographies
- unexpected geography requiring review
- denied autonomous systems
- hosting/data-center infrastructure
- proxy, VPN, and Tor indicators when available from IP2Location.io
- fraud score ceilings when available from the selected IP2Location.io plan
- non-global/private/reserved address misuse at the public lookup boundary
- silent policy drift during replay
- receipt mutation
- audit-stream deletion/reordering/tampering

## Explicit non-claims

3LOCKBOX does not claim that geolocation proves a human user's physical location or identity. IP geolocation is probabilistic network intelligence and is treated as one governed evidence source. A clean IP is not proof of trustworthiness.

The system also does not claim cryptographic non-repudiation: SHA-256 receipts and hash chaining provide deterministic integrity/tamper evidence, not identity-bound digital signatures.
