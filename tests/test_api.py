from fastapi.testclient import TestClient

import app.main as main
from app.ledger import LedgerStore
from app.models import Evidence
from app.receipts import ReceiptStore

client = TestClient(main.app)

async def fake_lookup(ip: str):
    return Evidence(ip=ip, country_code="US", country_name="United States of America", asn="15169", as_name="Google LLC", usage_type="ISP", is_proxy=False)

def isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(main.client, "lookup", fake_lookup)
    monkeypatch.setattr(main, "store", ReceiptStore(str(tmp_path / "receipts")))
    monkeypatch.setattr(main, "ledger", LedgerStore(str(tmp_path / "ledger.ndjson")))

def test_authorize_admit_binds_headers(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    response = client.post("/api/v1/authorize", json={"ip": "8.8.8.8", "expected_country": "US"})
    assert response.status_code == 204
    assert response.headers["x-3lockbox-decision"] == "ADMIT"
    assert len(response.headers["x-3lockbox-decision-hash"]) == 64
    assert len(response.headers["x-3lockbox-ledger-hash"]) == 64

def test_authorize_refuse_blocks_upstream(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    response = client.post("/api/v1/authorize", json={"ip": "8.8.8.8", "deny_countries": ["US"]})
    assert response.status_code == 403
    assert response.headers["x-3lockbox-decision"] == "REFUSE"

def test_admit_then_replay(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)
    admitted = client.post("/api/v1/admit", json={"ip": "8.8.8.8", "expected_country": "US"})
    assert admitted.status_code == 200
    replay = client.post("/api/v1/replay", json=admitted.json())
    assert replay.status_code == 200
    assert replay.json()["verified"] is True
    assert client.get("/api/v1/ledger/verify").json()["verified"] is True
