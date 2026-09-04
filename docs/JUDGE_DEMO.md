# 90-second Judge Demo

## 1. Prove the provider is live

Open `/docs` and call `GET /api/v1/lookup/8.8.8.8`.

Observe IP2Location.io-derived country, region, coordinates, ASN, and any plan-available security fields.

## 2. Prove admission is not lookup

Call `POST /api/v1/admit` with:

```json
{
  "ip": "8.8.8.8",
  "expected_country": "US",
  "deny_countries": [],
  "deny_asns": [],
  "block_datacenter": false
}
```

Observe `ADMIT` and the deterministic decision hash.

Now add `US` to `deny_countries`. The same IP2Location evidence crosses a different policy boundary and returns `REFUSE` with `COUNTRY_DENY`.

## 3. Prove gateway enforcement

Send the same request to `POST /api/v1/authorize`.

- ADMIT -> HTTP 204
- REVIEW or REFUSE -> HTTP 403

Inspect the `X-3LOCKBOX-*` response headers. This is the surface a reverse proxy can bind before upstream execution.

## 4. Prove replay

Take the receipt from step 2 and POST it to `/api/v1/replay`.

The service uses the stored evidence snapshot, not a fresh network lookup. `verified: true` proves the decision and hash reproduce under the same policy version.

## 5. Prove audit-chain integrity

Call `GET /api/v1/ledger/verify`.

The ledger reports `verified: true` and a chain head. Each event is linked to the preceding decision event by SHA-256.

That is the full claim: **live IP evidence, policy-bound consequence, deterministic replay, and tamper-evident event custody.**
