from pathlib import Path
from fastapi import FastAPI,HTTPException
from fastapi.responses import FileResponse
from .ip2location_client import IP2LocationClient,IP2LocationError
from .models import AdmissionReceipt,AdmissionRequest
from .policy import POLICY_VERSION,evaluate
from .receipts import ReceiptStore,build_receipt,compute_decision_hash

app=FastAPI(title="3LOCKBOX IP Admission Gate",version="1.0.0")
client=IP2LocationClient(); store=ReceiptStore(); INDEX=Path(__file__).parent/"static"/"index.html"
@app.get("/")
def ui(): return FileResponse(INDEX)
@app.get("/health")
def health(): return {"status":"ok","service":"3LOCKBOX IP Admission Gate","policy_version":POLICY_VERSION,"evidence_provider":"IP2Location.io"}
@app.get("/api/v1/lookup/{ip}")
async def lookup(ip:str):
    try: return await client.lookup(ip)
    except IP2LocationError as exc: raise HTTPException(status_code=400,detail=str(exc)) from exc
@app.post("/api/v1/admit",response_model=AdmissionReceipt)
async def admit(request:AdmissionRequest):
    try: evidence=await client.lookup(request.ip)
    except IP2LocationError as exc: raise HTTPException(status_code=400,detail=str(exc)) from exc
    decision,rules=evaluate(request,evidence); receipt=build_receipt(POLICY_VERSION,decision,request,evidence,rules); store.save(receipt); return receipt
@app.get("/api/v1/receipts/{decision_hash}",response_model=AdmissionReceipt)
def get_receipt(decision_hash:str):
    try: return store.load(decision_hash)
    except (FileNotFoundError,ValueError): raise HTTPException(status_code=404,detail="Receipt not found")
@app.post("/api/v1/replay")
def replay(receipt:AdmissionReceipt):
    if receipt.policy_version!=POLICY_VERSION: raise HTTPException(status_code=409,detail="Policy version mismatch")
    decision,rules=evaluate(receipt.input,receipt.evidence); h=compute_decision_hash(POLICY_VERSION,decision,receipt.input,receipt.evidence,rules)
    return {"verified":decision==receipt.decision and h==receipt.decision_hash,"original_decision":receipt.decision,"replayed_decision":decision,"original_hash":receipt.decision_hash,"replayed_hash":h,"policy_version":POLICY_VERSION}
