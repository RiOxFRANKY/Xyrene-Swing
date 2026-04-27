package com.ibm.developer.client;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import java.util.List;
import java.util.Map;

/**
 * Quarkus REST Client interface for the Python NIDS inference API.
 * Calls the FastAPI server running on localhost:8000.
 */
@Path("/")
@RegisterRestClient(configKey = "nids-api")
public interface NidsApiClient {

    @GET
    @Path("/health")
    @Produces(MediaType.APPLICATION_JSON)
    Map<String, Object> health();

    @POST
    @Path("/predict")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    NidsPrediction predict(NidsPredictRequest request);

    @POST
    @Path("/predict/batch")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    List<NidsPrediction> predictBatch(NidsBatchPredictRequest request);
}
