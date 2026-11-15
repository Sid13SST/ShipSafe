from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_read_item_found() -> None:
    resp = client.get("/items/1")
    assert resp.status_code == 200
    assert resp.json() == {"id": 1, "name": "alpha"}


def test_read_item_missing() -> None:
    assert client.get("/items/999").status_code == 404


def test_read_item_rejects_non_int() -> None:
    assert client.get("/items/abc").status_code == 422
