"""
Extract the 8 engineered features + labels from the parquet datasets
and save as clean CSVs for direct use.
"""

import os
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings("ignore")


def extract_8_features(features_dict: dict) -> dict:
    """
    Map raw CIC-FlowMeter flow features to the 8 features the Keras model expects.
    """
    f = features_dict
    syn = f.get("syn_flag_count", 0.0)
    ack = f.get("ack_flag_count", 0.0)
    
    return {
        "packet_size": f.get("average_packet_size", 0.0),
        "packets_per_sec": f.get("flow_packets_per_s", 0.0),
        "bytes_sent": f.get("total_length_of_fwd_packet", 0.0),
        "bytes_received": f.get("total_length_of_bwd_packet", 0.0),
        "connection_duration": f.get("flow_duration", 0.0),
        "unique_ports": f.get("dst_port", 0.0),
        "failed_logins": f.get("rst_flag_count", 0.0),
        "syn_ratio": syn / (syn + ack + 1e-9),
    }


def extract_all_flow_features(features_dict: dict) -> dict:
    """Extract ALL 78 flow features from the nested dict into flat columns."""
    return dict(features_dict)


def extract_semantic_flags(flags_dict: dict) -> dict:
    """Extract semantic flags into flat columns."""
    return dict(flags_dict)


def main():
    splits = {
        "train": os.path.join("dataset", "train", "train-00000-of-00001.parquet"),
        "test": os.path.join("dataset", "test", "test-00000-of-00001.parquet"),
        "validation": os.path.join("dataset", "validation", "validation-00000-of-00001.parquet"),
    }
    
    os.makedirs("dataset/extracted", exist_ok=True)
    
    for split_name, parquet_path in splits.items():
        if not os.path.exists(parquet_path):
            print(f"[WARN] {parquet_path} not found, skipping.")
            continue
        
        print(f"\n{'='*60}")
        print(f" Extracting: {split_name.upper()}")
        print(f"{'='*60}")
        
        df = pd.read_parquet(parquet_path)
        print(f"[INFO] Loaded {len(df):,} rows")
        
        # --- 1. Extract the 8 engineered features (for Keras model) ---
        print("[INFO] Extracting 8 engineered features...")
        feat_8 = pd.DataFrame([extract_8_features(row) for row in df["features"]])
        feat_8["label"] = df["label"].values
        feat_8["is_attack"] = df["is_attack"].values
        feat_8["flow_id"] = df["flow_id"].values
        
        path_8 = os.path.join("dataset", "extracted", f"{split_name}_8features.csv")
        feat_8.to_csv(path_8, index=False)
        print(f"  Saved -> {path_8} ({len(feat_8):,} rows, {feat_8.shape[1]} cols)")
        
        # --- 2. Extract ALL 78 flow features (for full analysis) ---
        print("[INFO] Extracting all 78 flow features...")
        feat_all = pd.DataFrame([extract_all_flow_features(row) for row in df["features"]])
        
        # Add semantic flags as columns
        flags = pd.DataFrame([extract_semantic_flags(row) for row in df["semantic_flags"]])
        feat_all = pd.concat([feat_all, flags], axis=1)
        
        feat_all["label"] = df["label"].values
        feat_all["is_attack"] = df["is_attack"].values
        feat_all["flow_id"] = df["flow_id"].values
        
        path_all = os.path.join("dataset", "extracted", f"{split_name}_all_features.csv")
        feat_all.to_csv(path_all, index=False)
        print(f"  Saved -> {path_all} ({len(feat_all):,} rows, {feat_all.shape[1]} cols)")
        
        # --- Summary ---
        print(f"\n  Label distribution:")
        print(f"    Benign: {(df['is_attack'] == 0).sum():,}")
        print(f"    Attack: {(df['is_attack'] == 1).sum():,}")
    
    print(f"\n{'='*60}")
    print(" EXTRACTION COMPLETE")
    print(f"{'='*60}")
    print(f"All CSVs saved to dataset/extracted/")


if __name__ == "__main__":
    main()
