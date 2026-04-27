"""
Evaluate the Keras NIDS model (nids_model.keras) + MinMaxScaler (nids_scaler.pkl)
on the new parquet datasets.

The model expects 8 engineered features derived from CIC-FlowMeter flow data:
  packet_size, packets_per_sec, bytes_sent, bytes_received,
  connection_duration, unique_ports, failed_logins, syn_ratio

The model outputs 4 classes via softmax.
"""

import os
import pickle
import warnings
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, ConfusionMatrixDisplay
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"


def extract_8_features(features_dict: dict) -> list:
    """
    Map raw CIC-FlowMeter flow features → the 8 features the Keras model expects.
    
    Mapping logic (derived from feature names and domain knowledge):
      packet_size       = average_packet_size
      packets_per_sec   = flow_packets_per_s
      bytes_sent        = total_length_of_fwd_packet
      bytes_received    = total_length_of_bwd_packet
      connection_duration = flow_duration
      unique_ports      = number of unique ports (dst_port used as proxy)
      failed_logins     = rst_flag_count (RST = failed/rejected connection)
      syn_ratio         = syn_flag_count / (syn_flag_count + ack_flag_count + 1e-9)
    """
    f = features_dict
    
    packet_size = f.get("average_packet_size", 0.0)
    packets_per_sec = f.get("flow_packets_per_s", 0.0)
    bytes_sent = f.get("total_length_of_fwd_packet", 0.0)
    bytes_received = f.get("total_length_of_bwd_packet", 0.0)
    connection_duration = f.get("flow_duration", 0.0)
    unique_ports = f.get("dst_port", 0.0)
    failed_logins = f.get("rst_flag_count", 0.0)
    
    syn = f.get("syn_flag_count", 0.0)
    ack = f.get("ack_flag_count", 0.0)
    syn_ratio = syn / (syn + ack + 1e-9)
    
    return [packet_size, packets_per_sec, bytes_sent, bytes_received,
            connection_duration, unique_ports, failed_logins, syn_ratio]


def main():
    print("[INFO] Loading Keras NIDS Model...")
    
    model_path = os.path.join("models", "nids_model.keras")
    scaler_path = os.path.join("models", "nids_scaler.pkl")
    
    model = tf.keras.models.load_model(model_path)
    print(f"  [OK] Keras model loaded. Input shape: {model.input_shape}, Output shape: {model.output_shape}")
    
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)
    print(f"  [OK] MinMaxScaler loaded ({scaler.n_features_in_} features)")
    print(f"       Feature names: {list(scaler.feature_names_in_)}")
    
    # --- Evaluate on each split ---
    splits = {
        "test": os.path.join("dataset", "test", "test-00000-of-00001.parquet"),
        "validation": os.path.join("dataset", "validation", "validation-00000-of-00001.parquet"),
    }
    
    for split_name, parquet_path in splits.items():
        if not os.path.exists(parquet_path):
            print(f"\n[WARN] {parquet_path} not found, skipping.")
            continue
            
        print(f"\n{'='*60}")
        print(f" EVALUATING ON: {split_name.upper()}")
        print(f"{'='*60}")
        
        df = pd.read_parquet(parquet_path)
        print(f"[INFO] Loaded {len(df):,} rows from {split_name}")
        
        # Extract the 8 features from the nested dict column
        print("[INFO] Extracting 8 engineered features from flow data...")
        X_raw = np.array([extract_8_features(row) for row in df["features"]], dtype=np.float32)
        
        # Replace inf/nan
        X_raw = np.nan_to_num(X_raw, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Scale
        X_scaled = scaler.transform(X_raw)
        
        # Ground truth
        y_true = df["is_attack"].values  # binary: 0=benign, 1=attack
        y_true_multi = df["label"].values  # multi-class labels
        
        # Predict in batches to save memory
        BATCH_SIZE = 10_000
        y_pred_probs = []
        for start in range(0, len(X_scaled), BATCH_SIZE):
            batch = X_scaled[start:start + BATCH_SIZE]
            probs = model.predict(batch, verbose=0)
            y_pred_probs.append(probs)
        
        y_pred_probs = np.concatenate(y_pred_probs, axis=0)
        y_pred_multi = np.argmax(y_pred_probs, axis=1)
        
        # For binary: map model output to binary (class 0 = benign, others = attack)
        y_pred_binary = (y_pred_multi != 0).astype(int)
        
        # --- Binary Results ---
        print(f"\n--- Binary Classification (Benign vs Attack) ---")
        print(f"Accuracy: {accuracy_score(y_true, y_pred_binary):.4%}")
        print(classification_report(y_true, y_pred_binary, 
              target_names=["Benign", "Attack"], digits=4, zero_division=0))
        
        cm_bin = confusion_matrix(y_true, y_pred_binary)
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        
        disp_bin = ConfusionMatrixDisplay(confusion_matrix=cm_bin, display_labels=["Benign", "Attack"])
        disp_bin.plot(ax=axes[0], cmap="Blues", values_format="d")
        axes[0].set_title(f"Binary Confusion Matrix\n({split_name} set)")
        
        # --- Multi-class Results ---
        print(f"\n--- Multi-Class Classification ---")
        print(f"Accuracy: {accuracy_score(y_true_multi, y_pred_multi):.4%}")
        
        # Only include classes that exist in ground truth
        unique_labels = sorted(set(y_true_multi) | set(y_pred_multi))
        print(classification_report(y_true_multi, y_pred_multi, 
              labels=unique_labels, digits=4, zero_division=0))
        
        cm_multi = confusion_matrix(y_true_multi, y_pred_multi, labels=unique_labels)
        disp_multi = ConfusionMatrixDisplay(confusion_matrix=cm_multi, display_labels=unique_labels)
        disp_multi.plot(ax=axes[1], cmap="Oranges", values_format="d")
        axes[1].set_title(f"Multi-Class Confusion Matrix\n({split_name} set)")
        
        plt.tight_layout()
        os.makedirs("models", exist_ok=True)
        save_path = os.path.join("models", f"keras_{split_name}_confusion_matrix.png")
        plt.savefig(save_path, dpi=150)
        plt.close()
        print(f"\n[PLOT] Saved -> {save_path}")


if __name__ == "__main__":
    main()
