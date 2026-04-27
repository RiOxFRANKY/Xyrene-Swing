package com.ibm.developer.client;

import java.util.List;

/**
 * Request body for POST /predict — single flow classification.
 */
public class NidsPredictRequest {
    
    private List<Double> features;

    public NidsPredictRequest() {}

    public NidsPredictRequest(List<Double> features) {
        this.features = features;
    }

    public NidsPredictRequest(double[] features) {
        this.features = new java.util.ArrayList<>(features.length);
        for (double f : features) {
            this.features.add(f);
        }
    }

    public List<Double> getFeatures() { return features; }
    public void setFeatures(List<Double> features) { this.features = features; }
}
