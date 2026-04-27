package com.ibm.developer.client;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Response DTO from the Python NIDS inference API.
 */
public class NidsPrediction {
    
    private int label;

    @JsonProperty("is_attack")
    private boolean isAttack;

    private double confidence;

    private List<Double> probabilities;

    public NidsPrediction() {}

    // --- Getters & Setters ---

    public int getLabel() { return label; }
    public void setLabel(int label) { this.label = label; }

    public boolean isAttack() { return isAttack; }
    public void setAttack(boolean attack) { isAttack = attack; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public List<Double> getProbabilities() { return probabilities; }
    public void setProbabilities(List<Double> probabilities) { this.probabilities = probabilities; }

    @Override
    public String toString() {
        return String.format("NidsPrediction{label=%d, attack=%s, confidence=%.4f}", label, isAttack, confidence);
    }
}
