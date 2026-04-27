"""
NIDS Model Loader & Inference

Loads the Keras NIDS model (nids_model.keras) and MinMaxScaler (nids_scaler.pkl),
provides predict/predict_batch functions for classification.

The model expects 8 features in this exact order:
  [packet_size, packets_per_sec, bytes_sent, bytes_received,
   connection_duration, unique_ports, failed_logins, syn_ratio]
"""

import os
import pickle
import warnings
import numpy as np

warnings.filterwarnings("ignore")
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf

# ─── Global Model State ──────────────────────────────────────────────────────

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
FEATURE_NAMES = [
    "packet_size", "packets_per_sec", "bytes_sent", "bytes_received",
    "connection_duration", "unique_ports", "failed_logins", "syn_ratio"
]

_model = None
_scaler = None


def load():
    """Load the Keras model and MinMaxScaler into memory."""
    global _model, _scaler

    model_path = os.path.join(MODELS_DIR, "nids_model.keras")
    scaler_path = os.path.join(MODELS_DIR, "nids_scaler.pkl")

    print("[INFO] Loading NIDS model...")
    _model = tf.keras.models.load_model(model_path)
    print(f"  [OK] Keras model loaded (input: {_model.input_shape}, output: {_model.output_shape})")

    with open(scaler_path, "rb") as f:
        _scaler = pickle.load(f)
    print(f"  [OK] MinMaxScaler loaded ({_scaler.n_features_in_} features)")

    return _model, _scaler


def predict(features: list[float]) -> dict:
    """
    Classify a single packet/flow from its 8 raw features.

    Args:
        features: List of 8 floats in the order defined by FEATURE_NAMES.

    Returns:
        dict with:
          - label: int (0=Benign, 1-3=Attack types)
          - is_attack: bool
          - confidence: float (max probability)
          - probabilities: list of 4 floats (softmax output)
    """
    if _model is None or _scaler is None:
        load()

    x = np.array([features], dtype=np.float32)
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    x_scaled = _scaler.transform(x)

    probs = _model.predict(x_scaled, verbose=0)[0]
    label = int(np.argmax(probs))

    return {
        "label": label,
        "is_attack": label != 0,
        "confidence": float(probs[label]),
        "probabilities": [float(p) for p in probs],
    }


def predict_batch(features_batch: list[list[float]]) -> list[dict]:
    """
    Classify a batch of packets/flows.

    Args:
        features_batch: List of N lists, each containing 8 floats.

    Returns:
        List of N result dicts (same format as predict()).
    """
    if _model is None or _scaler is None:
        load()

    x = np.array(features_batch, dtype=np.float32)
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    x_scaled = _scaler.transform(x)

    probs = _model.predict(x_scaled, verbose=0)
    labels = np.argmax(probs, axis=1)

    results = []
    for i in range(len(labels)):
        label = int(labels[i])
        results.append({
            "label": label,
            "is_attack": label != 0,
            "confidence": float(probs[i][label]),
            "probabilities": [float(p) for p in probs[i]],
        })
    return results


# ─── Quick Self-Test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    load()
    sample = [64.25, 3629.76, 90.0, 122.0, 1102.0, 53.0, 0.0, 0.0]
    print(f"\n[TEST] Input:  {sample}")
    result = predict(sample)
    print(f"[TEST] Output: {result}")

    batch = [sample, [0.0, 9404.39, 0.0, 0.0, 319.0, 9642.0, 0.0, 0.0]]
    results = predict_batch(batch)
    print(f"\n[TEST] Batch ({len(batch)} samples):")
    for i, r in enumerate(results):
        print(f"  [{i}] label={r['label']}, attack={r['is_attack']}, conf={r['confidence']:.4f}")
