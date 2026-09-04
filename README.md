# 3LOCKBOX — Deterministic IP Admission Gate

[![test](https://github.com/Kamanaka5502/3lockbox-ip-admission-gate/actions/workflows/test.yml/badge.svg)](https://github.com/Kamanaka5502/3lockbox-ip-admission-gate/actions/workflows/test.yml)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB)
![FastAPI](https://img.shields.io/badge/FastAPI-0.116-009688)
![License](https://img.shields.io/badge/license-MIT-blue)

## Live deployment

**Public demo:** https://threelockbox-ip-admission-gate.onrender.com

**Interactive API:** https://threelockbox-ip-admission-gate.onrender.com/docs

**Health / runtime state:** https://threelockbox-ip-admission-gate.onrender.com/health

The public Render deployment runs from `main` and is pinned to Python 3.12 for reproducible builds.

---

**IP intelligence should not merely describe a connection. It should govern whether that connection is allowed to matter.**

3LOCKBOX is an enforcement layer built on **IP2Location.io**. It converts live IP geolocation/security evidence into one of three governed consequences:

- **ADMIT** — evidence satisfies the active policy.
- **REVIEW** — evidence is incomplete, inconsistent, or requires operator attention.
- **REFUSE** — a hard policy boundary is violated.

Every decision emits two independent proof layers:

1. a **deterministic decision receipt** whose SHA-256 hash can be replayed from the same input, evidence snapshot, rules, and policy version;
2. a **tamper-evident append-only ledger** that chains decision events in execution order.

> **Lookup is evidence. Policy is authority. Consequence is bound only after validation.**

Built for the **IP2Location Programming Contest 2026**.

---

## The 30-second version

Most IP tools stop here:

```text
IP → country / city / ASN / proxy metadata
```

3LOCKBOX continues through the execution boundary:

```text
Candidate IP
    ↓
Public-IP admissibility check
    ↓
IP2Location.io evidence acquisition
    ↓
Normalized evidence envelope
    ↓
Versioned deterministic policy
    ├── ADMIT
    ├── REVIEW
    └── REFUSE
    ↓
Deterministic receipt hash
    ↓
Append-only hash-chain ledger
    ↓
Replay / verify / gateway enforcement
```

The provider tells us what is observed. **3LOCKBOX determines whether execution is admissible.**

---

## Why this is different

### IP2Location is a control input, not dashboard decoration

The application uses IP2Location.io as a core evidence provider for IPv4/IPv6 location and network intelligence. When the configured plan exposes advanced security fields, 3LOCKBOX also consumes proxy, VPN, Tor, data-center, threat, and fraud-score evidence.

### Decisions are deterministic and replayable

A receipt hash is derived from canonicalized:

```text
request + IP2Location evidence snapshot + fired rules + policy version + decision
```

Timestamps are deliberately excluded from the proof hash. The same evidence under the same policy produces the same decision proof.

### Audit ordering is independently tamper-evident

Decision determinism and event ordering are different guarantees. 3LOCKBOX keeps them separate.

The local ledger chains every event:

```text
entry[n] = SHA256(
    sequence
  + decision_hash
  + decision
  + policy_version
  + entry_hash[n-1]
)
```

That exposes deletion, reordering, or mutation in the local event stream without destroying deterministic replay of the underlying decision.

### It can sit in front of a real service

`POST /api/v1/authorize` is a machine enforcement surface for reverse proxies, API gateways, and middleware:

- `204` only when the result is **ADMIT**
- `403` when the result is **REVIEW** or **REFUSE**

The response binds:

- `X-3LOCKBOX-Decision`
- `X-3LOCKBOX-Decision-Hash`
- `X-3LOCKBOX-Ledger-Hash`
- `X-3LOCKBOX-Policy`

The protected upstream does not need to trust a human-readable dashboard; it can enforce the consequence directly.

---

## Evidence and policy boundaries

| Evidence / boundary | Behavior |
|---|---|
| Invalid / private / reserved IP | lookup refused before provider call |
| Country deny list | **REFUSE** |
| Explicit country allow set miss | **REFUSE** |
| Expected-country mismatch | **REVIEW** |
| ASN deny list | **REFUSE** |
| Data-center / hosting classification | **REVIEW** when enabled |
| Proxy indicator | **REFUSE** when enabled |
| VPN indicator | **REFUSE** when enabled |
| Tor indicator | **REFUSE** when enabled |
| Fraud score above ceiling | **REFUSE** when configured |
| Non-empty threat signal | **REVIEW** |
| Missing country evidence | **REVIEW** rather than silent admit |

Advanced proxy/fraud fields depend on the configured IP2Location.io plan. 3LOCKBOX never fabricates evidence that the provider did not return.

---

## API surfaces

| Endpoint | Purpose |
|---|---|
| `GET /health` | runtime + policy + ledger state |
| `GET /api/v1/lookup/{ip}` | normalized IP2Location evidence |
| `POST /api/v1/admit` | full decision receipt |
| `POST /api/v1/authorize` | gateway enforcement response |
| `POST /api/v1/replay` | deterministic offline replay |
| `GET /api/v1/receipts/{hash}` | persisted receipt retrieval |
| `GET /api/v1/ledger` | audit-ledger tail |
| `GET /api/v1/ledger/verify` | verify the complete hash chain |
| `GET /docs` | interactive OpenAPI console |

---

## Judge path: 90 seconds

The fastest way to evaluate the full architecture is in [`docs/JUDGE_DEMO.md`](docs/JUDGE_DEMO.md).

In sequence:

1. Query `8.8.8.8` through IP2Location.io.
2. Admit it under a US-expected policy.
3. Add `US` to the deny set and observe the same evidence bind a **REFUSE** consequence.
4. Send the policy to `/api/v1/authorize` and observe HTTP enforcement semantics.
5. Replay the receipt without re-querying the provider.
6. Verify the event-order ledger.

That demonstrates **evidence → authority → consequence → proof**, not merely data presentation.

---

## Quick start

```bash
git clone https://github.com/Kamanaka5502/3lockbox-ip-admission-gate.git
cd 3lockbox-ip-admission-gate
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

Install:

```bash
pip install -r requirements.txt
```

Optional API key:

```bash
cp .env.example .env
```

Then set:

```text
IP2LOCATION_API_KEY=your_key_here
```

IP2Location.io also supports limited keyless basic lookup.

Run:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000
```

Interactive API:

```text
http://localhost:8000/docs
```

---

## Example admission request

```bash
curl -X POST http://localhost:8000/api/v1/admit \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "8.8.8.8",
    "expected_country": "US",
    "deny_countries": [],
    "deny_asns": [],
    "block_datacenter": false,
    "deny_proxy": false,
    "deny_vpn": false,
    "deny_tor": false,
    "max_fraud_score": null
  }'
```

Representative response shape:

```json
{
  "policy_version": "3lockbox-ip-policy/1.1",
  "decision": "ADMIT",
  "decision_hash": "<64 hex characters>",
  "evidence": {
    "ip": "8.8.8.8",
    "country_code": "US",
    "asn": "15169",
    "source": "IP2Location.io"
  },
  "rules": [],
  "observed_at": "<UTC timestamp>"
}
```

---

## Deterministic replay

Replay uses the stored evidence snapshot. It does **not** perform a fresh IP2Location lookup.

```bash
curl -X POST http://localhost:8000/api/v1/replay \
  -H "Content-Type: application/json" \
  -d @receipt.json
```

Why this matters: historical truth should not silently change because the network, provider database, or IP allocation changed after the original decision.

---

## Ledger verification

```bash
curl http://localhost:8000/api/v1/ledger/verify
```

Receipt proofs answer **“does this decision reproduce?”**

Ledger proofs answer **“has the local decision sequence been altered?”**

They are related, but not interchangeable.

---

## Tests

```bash
python -m pytest -q
```

Coverage includes:

- clean ADMIT path
- country REFUSE
- country mismatch REVIEW
- ASN REFUSE
- data-center REVIEW
- proxy / VPN / Tor REFUSE
- fraud-score ceiling
- private/reserved address rejection
- deterministic decision hashing
- timestamp-independent proof stability
- valid ledger chain
- tamper detection
- gateway 204/403 enforcement semantics
- gateway proof headers
- admit → replay verification

CI runs automatically on every push and pull request.

---

## Docker

```bash
docker build -t 3lockbox-ip-admission-gate .
docker run --rm -p 8000:8000 3lockbox-ip-admission-gate
```

With an IP2Location.io API key:

```bash
docker run --rm -p 8000:8000 \
  -e IP2LOCATION_API_KEY=your_key_here \
  3lockbox-ip-admission-gate
```

---

## Architecture and security model

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — proof separation, state flow, enforcement surfaces
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what the system does and does not claim
- [`docs/JUDGE_DEMO.md`](docs/JUDGE_DEMO.md) — rapid evaluator path
- [`integrations/nginx.conf`](integrations/nginx.conf) — reverse-proxy enforcement contract

---

## Explicit non-claims

IP geolocation is network intelligence; it is **not** proof of a person's physical location or identity. A clean IP is not proof that a user is trustworthy.

SHA-256 receipts and hash chaining provide deterministic integrity and tamper evidence; they are not identity-bound digital signatures.

The system's claim is narrower and testable:

> Given an IP2Location evidence snapshot and a versioned policy, 3LOCKBOX can deterministically bind a consequence, reproduce that consequence later, and verify the integrity/order of its local decision evidence.

---

## Contest positioning

### Creativity

IP geolocation becomes an **admission primitive** rather than a passive lookup result. Decision determinism and audit ordering are modeled as separate proof dimensions.

### Functionality

The repository is a runnable application: browser console, REST API, gateway enforcement, persistence, deterministic replay, audit ledger, Docker, OpenAPI, tests, CI, and a public deployment.

### Evaluation surface

A judge can move from public URL to verified behavior immediately, while the browser interface exposes the complete consequence lifecycle visually.

---

## License

MIT © 2026 Samantha Greenwell Revita / Elyria Systems
