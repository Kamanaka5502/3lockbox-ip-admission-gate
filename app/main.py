from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from .ip2location_client import IP2LocationClient, IP2LocationError
from .ledger import LedgerStore
from .models import AdmissionReceipt, AdmissionRequest, Decision
from .policy import POLICY_VERSION, evaluate
from .receipts import ReceiptStore, build_receipt, compute_decision_hash

app = FastAPI(
    title="3LOCKBOX IP Admission Gate",
    version="1.2.0",
    description="Deterministic IP admission control using IP2Location.io evidence, replayable receipts, a tamper-evident audit ledger, and a live holographic consequence console.",
)
client = IP2LocationClient()
store = ReceiptStore()
ledger = LedgerStore()
STATIC_DIR = Path(__file__).parent / "static"
STATIC_INDEX = STATIC_DIR / "index.html"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _persist(receipt: AdmissionReceipt) -> dict:
    store.save(receipt)
    return ledger.append(receipt)


async def _evaluate_request(request: AdmissionRequest) -> tuple[AdmissionReceipt, dict]:
    try:
        evidence = await client.lookup(request.ip)
    except IP2LocationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    decision, rules = evaluate(request, evidence)
    receipt = build_receipt(POLICY_VERSION, decision, request, evidence, rules)
    ledger_entry = _persist(receipt)
    return receipt, ledger_entry


@app.get("/")
def ui():
    return FileResponse(STATIC_INDEX)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "3LOCKBOX IP Admission Gate",
        "version": "1.2.0",
        "console": "holographic",
        "policy_version": POLICY_VERSION,
        "evidence_provider": "IP2Location.io",
        "ledger": ledger.verify(),
    }


@app.get("/api/v1/lookup/{ip}")
async def lookup(ip: str):
    try:
        return await client.lookup(ip)
    except IP2LocationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/admit", response_model=AdmissionReceipt)
async def admit(request: AdmissionRequest):
    receipt, _ = await _evaluate_request(request)
    return receipt


@app.post("/api/v1/authorize")
async def authorize(request: AdmissionRequest):
    """Gateway enforcement: only ADMIT returns HTTP 204; REVIEW/REFUSE return 403."""
    receipt, ledger_entry = await _evaluate_request(request)
    status_code = 204 if receipt.decision == Decision.ADMIT else 403
    return Response(
        status_code=status_code,
        headers={
            "X-3LOCKBOX-Decision": receipt.decision.value,
            "X-3LOCKBOX-Decision-Hash": receipt.decision_hash,
            "X-3LOCKBOX-Ledger-Hash": ledger_entry["entry_hash"],
            "X-3LOCKBOX-Policy": receipt.policy_version,
        },
    )


@app.get("/api/v1/receipts/{decision_hash}", response_model=AdmissionReceipt)
def get_receipt(decision_hash: str):
    try:
        return store.load(decision_hash)
    except (FileNotFoundError, ValueError):
        raise HTTPException(status_code=404, detail="Receipt not found")


@app.post("/api/v1/replay")
def replay(receipt: AdmissionReceipt):
    if receipt.policy_version != POLICY_VERSION:
        raise HTTPException(
            status_code=409,
            detail=f"Policy version mismatch: receipt={receipt.policy_version}, runtime={POLICY_VERSION}",
        )
    decision, rules = evaluate(receipt.input, receipt.evidence)
    recalculated = compute_decision_hash(
        POLICY_VERSION, decision, receipt.input, receipt.evidence, rules
    )
    return {
        "verified": decision == receipt.decision and recalculated == receipt.decision_hash,
        "original_decision": receipt.decision,
        "replayed_decision": decision,
        "original_hash": receipt.decision_hash,
        "replayed_hash": recalculated,
        "policy_version": POLICY_VERSION,
    }


@app.get("/api/v1/ledger/verify")
def verify_ledger():
    return ledger.verify()


@app.get("/api/v1/ledger")
def ledger_tail(limit: int = Query(default=25, ge=1, le=250)):
    return {"entries": ledger.tail(limit), "verification": ledger.verify()}
