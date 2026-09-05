# 3LOCKBOX Boundary Content Pack

This file is the canonical copy deck for hover cards, map extremities, mathematical orbit strings, and demo event language.

## Hover cards

### Candidate Surface
**Purpose:** Establish input admissibility before any provider lookup or downstream effect.

**Evidence required:** A syntactically valid, globally routable IPv4 or IPv6 address.

**Consequence power:** Allows evidence acquisition to proceed.

**Failure closure:** Private, loopback, reserved, link-local, multicast, and invalid inputs stop before provider access.

**Blind spot addressed:** Many pipelines begin processing before input admissibility is established.

**Math:** `x ∈ PublicIP ⇒ acquire(x)`

### Evidence Acquisition Boundary
**Purpose:** Normalize IP2Location.io network intelligence into a governed evidence envelope.

**Evidence required:** Country, ASN, usage classification, and security/risk fields when the configured provider plan exposes them.

**Consequence power:** Creates the evidence snapshot consumed by policy.

**Failure closure:** Missing or insufficient evidence cannot silently become a clean admit.

**Blind spot addressed:** Lookup output is evidence, not authority and not final truth.

**Math:** `E = normalize(IP2Location(x))`

### Policy Admission Boundary
**Purpose:** Evaluate whether normalized evidence survives the active versioned rule set.

**Evidence required:** Evidence envelope + active policy version + explicit allow/deny/risk thresholds.

**Consequence power:** Computes `ADMIT`, `REVIEW`, or `REFUSE`.

**Failure closure:** Hard deny matches and configured risk ceilings block motion before effect binds.

**Blind spot addressed:** Rules are not governance unless their result is bound to execution.

**Math:** `decision = P_v(E)`

### Consequence Lock Boundary
**Purpose:** Bind the only outcome allowed to affect the protected execution path.

**Evidence required:** Completed evaluated state under a known policy version.

**Consequence power:** HTTP enforcement and machine-readable consequence state.

**Failure closure:** Unresolved review or refusal never becomes implicit success.

**Blind spot addressed:** Analytics can describe risk without ever controlling consequence.

**Math:** `bind(c) iff c ∈ {A,R,F}`

### Proof Emission Boundary
**Purpose:** Seal decision truth into a deterministic replayable receipt.

**Evidence required:** Canonical request + evidence snapshot + fired rules + policy version + decision.

**Consequence power:** Emits a deterministic SHA-256 decision proof.

**Failure closure:** Replay mismatch exposes integrity or policy-state divergence.

**Blind spot addressed:** Historical decisions should be reproducible, not merely logged.

**Math:** `H_d = SHA256(request || E || rules || P_v || c)`

### Ledger Continuity Boundary
**Purpose:** Preserve local decision ordering independently from deterministic receipt replay.

**Evidence required:** Previous ledger hash + sequence + decision proof + decision + policy version.

**Consequence power:** Appends a tamper-evident event-order proof.

**Failure closure:** Mutation, deletion, or reordering becomes detectable by chain verification.

**Blind spot addressed:** Logs record events; custody chains make sequence integrity testable.

**Math:** `H_n = SHA256(n || H_d || c || P_v || H_(n-1))`

### Authority Custody Boundary
**Purpose:** Separate observation from the authority allowed to bind consequence.

**Evidence required:** Versioned policy evaluation and intact execution path.

**Consequence power:** Only validated policy output may authorize effect.

**Failure closure:** No valid custody path means no consequence is admitted.

**Blind spot addressed:** Visibility, scoring, and dashboards are not equivalent to execution authority.

**Math:** `authority != evidence; authority = valid(P_v,E)`

### Replay Integrity Boundary
**Purpose:** Recompute past truth from the stored evidence snapshot rather than a fresh external lookup.

**Evidence required:** Original receipt snapshot + original policy version.

**Consequence power:** Confirms whether the same decision proof reproduces.

**Failure closure:** Historical truth cannot drift silently with later provider or network changes.

**Blind spot addressed:** Re-querying the present is not the same as replaying the past.

**Math:** `replay(snapshot,P_v) = H_d'`

### Admissibility Threshold
**Purpose:** Convert configured country, ASN, hosting, proxy, VPN, Tor, and fraud conditions into explicit gates.

**Evidence required:** Observed provider fields and operator-selected policy thresholds.

**Consequence power:** Escalates or refuses before protected effect occurs.

**Failure closure:** Threshold breach is explicit and machine enforceable.

**Blind spot addressed:** Risk indicators only matter when tied to a defined boundary and outcome.

**Math:** `risk(E) <= tau => eligible`

## Extremity map labels

- PRE-EFFECT BOUNDARY
- EVIDENCE NORMALIZATION
- ADMISSIBILITY THRESHOLD
- POLICY AUTHORITY
- CONSEQUENCE LOCK
- PROOF EMISSION
- LEDGER CONTINUITY
- REPLAY INTEGRITY
- AUTHORITY CUSTODY
- REFUSAL CLOSURE

## Orbit strings

- `x ∈ PublicIP`
- `E = normalize(IP2Location(x))`
- `decision = P_v(E)`
- `bind(c) <=> c ∈ {A,R,F}`
- `H_d = SHA256(request||E||rules||P_v||c)`
- `H_n = SHA256(n||H_d||H_(n-1))`
- `risk(E) <= tau => eligible`
- `∇ evidence · Σ rules · Π custody`
- `(lat,lon) · ASN · usage · threat`
- `replay(snapshot,P_v) = H_d'`
- `effect <- admitted(state)`
- `authority != evidence`

## State event language

### PENDING
- CANDIDATE ACQUIRED
- IP2LOCATION EVIDENCE
- POLICY EVALUATION
- CONSEQUENCE BINDING
- PROOF EMISSION

### ADMIT
- EXECUTION ADMITTED
- EFFECT MAY BIND
- RECEIPT SEALED
- LEDGER APPENDED

### REVIEW
- EXECUTION HELD FOR REVIEW
- EFFECT REMAINS UNBOUND
- UNCERTAINTY PRESERVED

### REFUSE
- EXECUTION REFUSED
- HARD BOUNDARY FIRED
- EFFECT DENIED BEFORE BINDING

## UI labels

- RUN HOLOGRAPHIC DEMO
- PAUSE MOTION
- EXECUTE ADMISSION
- CLEAN ADMIT
- COUNTRY MISMATCH
- HARD REFUSE
- VERIFY CHAIN
- EXTREMITY / BOUNDARY INTELLIGENCE

## Copy discipline

Use narrow, testable claims. The interface should say that a boundary or proof is implemented and verifiable when that behavior exists in the code. Avoid universal claims that all other systems lack the same capability. Prefer `blind spot addressed`, `common omission`, or `boundary modeled explicitly`.
