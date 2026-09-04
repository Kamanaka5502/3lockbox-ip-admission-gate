# 3LOCKBOX IP Admission Gate

A deterministic IP-intelligence admission system built for the **IP2Location Programming Contest 2026**.

`3LOCKBOX` converts IP geolocation evidence into one of three governed outcomes:

- **ADMIT** — evidence satisfies the active policy.
- **REVIEW** — evidence is incomplete or materially inconsistent.
- **REFUSE** — a hard policy boundary is violated.

Every decision produces a replayable receipt containing the normalized IP2Location evidence, fired rules, policy version, decision, and a deterministic SHA-256 proof hash.

## Why this exists

Most IP intelligence systems stop at lookup:

`IP -> location metadata`

3LOCKBOX adds an enforcement boundary:

`IP -> IP2Location evidence -> policy evaluation -> consequence -> replayable proof`

The lookup is not the decision. Execution is admitted only after the evidence survives the active policy.

## Core IP2Location integration

The application uses the official **IP2Location.io IP Geolocation API** as a core component.

By default it can use IP2Location.io's keyless endpoint for basic lookups. If you have an API key, set `IP2LOCATION_API_KEY` to use it.

## Features

- IPv4 and IPv6 validation
- IP2Location.io geolocation lookup
- Deterministic policy engine
- Country allow/deny enforcement
- Expected-country mismatch detection
- ASN deny-list enforcement
- Data-center / hosting review policy
- Fail-closed handling for non-routable addresses
- Replayable decision receipts
- Deterministic SHA-256 decision hash
- Local receipt persistence
- REST API
- Browser UI
- Docker support
- Automated tests

## Quick start

### 1. Clone

```bash
git clone https://github.com/Kamanaka5502/3lockbox-ip-admission-gate.git
cd 3lockbox-ip-admission-gate
```

### 2. Create a virtual environment

```bash
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

### 3. Install

```bash
pip install -r requirements.txt
```

### 4. Optional: configure an IP2Location.io API key

```bash
cp .env.example .env
```

Then set:

```text
IP2LOCATION_API_KEY=your_key_here
```

The app also works with IP2Location.io's public keyless lookup where available.

### 5. Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000
```

## Example API call

```bash
curl -X POST http://localhost:8000/api/v1/admit \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "8.8.8.8",
    "expected_country": "US",
    "deny_countries": [],
    "deny_asns": [],
    "block_datacenter": false
  }'
```

Example response shape:

```json
{
  "decision": "ADMIT",
  "decision_hash": "sha256...",
  "policy_version": "3lockbox-ip-policy/1.0",
  "evidence": {
    "ip": "8.8.8.8",
    "country_code": "US",
    "asn": "15169"
  },
  "rules": []
}
```

## Decision lifecycle

```text
                  ┌──────────────────────┐
                  │   Candidate IP       │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ IP syntax / routable │
                  │ boundary validation  │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │  IP2Location.io      │
                  │  evidence lookup     │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ deterministic policy │
                  │ evaluation           │
                  └─────┬────────┬───────┘
                        │        │
               ┌────────┘        └─────────┐
               ▼                           ▼
          hard violation             uncertainty
               │                           │
               ▼                           ▼
            REFUSE                      REVIEW
                        \
                         \ no violation
                          ▼
                         ADMIT
                          │
                          ▼
                  replayable receipt
                  + SHA-256 proof
```

## Deterministic replay

Each receipt stores the evidence snapshot used for the original decision. Replay does **not** re-query the network. It re-evaluates the stored evidence under the same policy version and verifies the deterministic hash.

```bash
curl -X POST http://localhost:8000/api/v1/replay \
  -H "Content-Type: application/json" \
  -d @receipt.json
```

## Receipt storage

Receipts are written to:

```text
data/receipts/<decision_hash>.json
```

They can be retrieved with:

```text
GET /api/v1/receipts/{decision_hash}
```

## Tests

```bash
pytest -q
```

The tests cover:

- admit path
- refuse path
- review path
- private/reserved address handling
- deterministic receipt hashing
- replay integrity

## Docker

```bash
docker build -t 3lockbox-ip-admission-gate .
docker run --rm -p 8000:8000 3lockbox-ip-admission-gate
```

With an API key:

```bash
docker run --rm -p 8000:8000 \
  -e IP2LOCATION_API_KEY=your_key_here \
  3lockbox-ip-admission-gate
```

## Contest positioning

The project is intentionally more than a geolocation viewer. IP2Location data is treated as evidence entering a governed execution boundary. The system binds consequences only after policy validation and emits a proof artifact that can be replayed later.

This gives judges three concrete dimensions to evaluate:

1. **Creativity** — geolocation becomes an admissibility primitive, not just display data.
2. **Functionality** — a complete application with API, browser UI, persistence, replay, and tests.
3. **Auditability** — each decision is explainable and hash-verifiable.

## License

MIT.
