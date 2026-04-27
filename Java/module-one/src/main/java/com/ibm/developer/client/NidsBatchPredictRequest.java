package com.ibm.developer.client;

import java.util.List;

/**
 * Request body for POST /predict/batch — batch flow classification.
 */
public class NidsBatchPredictRequest {
    
    private List<List<Double>> features;

    public NidsBatchPredictRequest() {}

    public NidsBatchPredictRequest(List<List<Double>> features) {
        this.features = features;
    }

    public List<List<Double>> getFeatures() { return features; }
    public void setFeatures(List<List<Double>> features) { this.features = features; }
}
