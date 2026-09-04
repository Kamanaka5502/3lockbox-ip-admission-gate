# 3LOCKBOX Architecture

## Execution boundary

3LOCKBOX separates **observation** from **authority**.

```text
candidate connection
        |
        v
IP syntax/routability gate
        |
        v
IP2Location.io evidence acquisition
        |
        v
normalized evidence envelope
        |
        v
versioned deterministic policy
   |          |          |
 ADMIT      REVIEW      REFUSE
   |          |          |
   +----------+----------+
              |
              v
deterministic decision receipt
              |
              v
append-only hash-chain ledger
              |
              v
replay / verify / gateway enforcement
```

The IP2Location response is evidence, not authority. Authority is exercised only by the versioned policy engine.

## Two proof layers

### Decision proof

`decision_hash = SHA256(canonical(input + evidence + rules + policy + decision))`

For the same admitted evidence under the same policy, the proof hash is identical. Timestamps are excluded from this hash.

### Event-order proof

The local ledger chains each decision event to the previous event:

`entry_hash[n] = SHA256(sequence + decision_hash + decision + policy + entry_hash[n-1])`

This creates different guarantees:

- receipt hash -> content determinism
- ledger hash -> ordering / tamper evidence

Conflating these would destroy replay determinism, so they remain separate dimensions.

## Enforcement surfaces

- `POST /api/v1/admit` — full receipt for operators and applications.
- `POST /api/v1/authorize` — reverse-proxy enforcement: HTTP 204 only for ADMIT, 403 otherwise.
- `POST /api/v1/replay` — re-evaluate stored evidence without network lookup.
- `GET /api/v1/ledger/verify` — verify the full local hash chain.

## Evidence degradation

IP2Location.io exposes different evidence depth by plan. Basic geolocation works without an API key; advanced security fields such as fraud score and detailed proxy metadata require an appropriate plan.

3LOCKBOX does not invent absent evidence. Rules fire only when their required evidence is present. Missing country evidence routes to REVIEW rather than being silently admitted.
