"""Minimal FastAPI app used as the "clean" target for ShipSafe's CI gates.

It is intentionally tiny: the point of this repository is the pipeline, not the
app. It should stay free of known issues so the gates pass on it.
"""

from fastapi import FastAPI, HTTPException

app = FastAPI(title="ShipSafe demo app", version="0.1.0")

_ITEMS: dict[int, str] = {1: "alpha", 2: "beta"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/items/{item_id}")
def read_item(item_id: int) -> dict[str, object]:
    name = _ITEMS.get(item_id)
    if name is None:
        raise HTTPException(status_code=404, detail="item not found")
    return {"id": item_id, "name": name}
