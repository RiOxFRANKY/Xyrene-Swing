package com.ibm.developer.service;

import com.ibm.developer.client.NidsApiClient;
import com.ibm.developer.client.NidsBatchPredictRequest;
import com.ibm.developer.client.NidsPredictRequest;
import com.ibm.developer.client.NidsPrediction;
import com.ibm.developer.model.NidsFeatures;
import com.ibm.developer.model.Packet;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * High-level service that orchestrates the full NIDS pipeline:
 * 1. Extract 8 features from a packet via FeatureExtractorService
 * 2. Send features to the Python Keras model via NidsApiClient
 * 3. Return the classification result
 */
@ApplicationScoped
public class NidsClassificationService {

    private static final Logger logger = Logger.getLogger(NidsClassificationService.class);

    @Inject
    FeatureExtractorService featureExtractor;

    @Inject
    @RestClient
    NidsApiClient nidsApi;

    /**
     * Classify a single packet: extract features -> call Python API -> return result.
     */
    public NidsPrediction classify(Packet packet) {
        NidsFeatures features = featureExtractor.extractFeatures(packet);
        logger.debugv("Extracted features: {0}", features);

        NidsPredictRequest request = new NidsPredictRequest(features.toArray());
        NidsPrediction prediction = nidsApi.predict(request);

        logger.infov("Packet {0} classified: {1}", packet.getId(), prediction);
        return prediction;
    }

    /**
     * Classify a batch of packets in a single API call for efficiency.
     */
    public List<NidsPrediction> classifyBatch(List<Packet> packets) {
        List<List<Double>> featureBatch = new ArrayList<>(packets.size());

        for (Packet packet : packets) {
            NidsFeatures features = featureExtractor.extractFeatures(packet);
            double[] arr = features.toArray();
            List<Double> featureList = new ArrayList<>(arr.length);
            for (double v : arr) {
                featureList.add(v);
            }
            featureBatch.add(featureList);
        }

        NidsBatchPredictRequest request = new NidsBatchPredictRequest(featureBatch);
        List<NidsPrediction> predictions = nidsApi.predictBatch(request);

        logger.infov("Batch classified: {0} packets", packets.size());
        return predictions;
    }

    /**
     * Check if the Python inference server is reachable.
     */
    public boolean isModelServerHealthy() {
        try {
            var health = nidsApi.health();
            return "ok".equals(health.get("status"));
        } catch (Exception e) {
            logger.warnv("NIDS API health check failed: {0}", e.getMessage());
            return false;
        }
    }
}
