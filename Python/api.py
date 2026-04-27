"""
Xyrene NIDS Inference API

FastAPI server that exposes the Keras NIDS model for the Java Quarkus backend.

Endpoints:
  GET  /health         - Health check
  POST /predict        - Classify a single flow (8 features)
  POST /predict/batch  - Classify multiple flows

Usage:
  python api.py                        # Start on default port 8000
  python api.py --port 9000            # Start on custom port
"""

import argparse
from fastapi import FastAPI
from pydantic import BaseModel
from load_model import load, predict, predict_batch

app = FastAPI(
    title="Xyrene NIDS Inference API",
    description="Network Intrusion Detection System - Keras Model Inference",
    version="1.0.0",
)


# ─── Request / Response Models ────────────────────────────────────────────────

class PredictRequest(BaseModel):
    features: list[float]

class BatchPredictRequest(BaseModel):
    features: list[list[float]]

class PredictResponse(BaseModel):
    label: int
    is_attack: bool
    confidence: float
    probabilities: list[float]


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    load()

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/predict", response_model=PredictResponse)
async def api_predict(req: PredictRequest):
    if len(req.features) != 8:
        return {"error": f"Expected 8 features, got {len(req.features)}"}
    return predict(req.features)

@app.post("/predict/batch", response_model=list[PredictResponse])
async def api_predict_batch(req: BatchPredictRequest):
    return predict_batch(req.features)


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="Xyrene NIDS Inference API")
    parser.add_argument("--port", type=int, default=8000, help="Port to run on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind")
    args = parser.parse_args()

    print(f"\n[INFO] Starting inference server on http://{args.host}:{args.port}")
    print(f"[INFO] Docs available at http://localhost:{args.port}/docs")
    uvicorn.run(app, host=args.host, port=args.port)
