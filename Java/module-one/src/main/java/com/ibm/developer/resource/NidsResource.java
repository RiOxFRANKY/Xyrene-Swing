package com.ibm.developer.resource;

import com.ibm.developer.client.NidsPrediction;
import com.ibm.developer.model.Packet;
import com.ibm.developer.service.NidsClassificationService;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Map;

/**
 * REST API endpoint for the Xyrene NIDS.
 *
 * POST /api/nids/classify       - Classify a single packet
 * POST /api/nids/classify/batch - Classify a batch of packets
 * GET  /api/nids/health         - Check Python model server health
 */
@Path("/api/nids")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class NidsResource {

    @Inject
    NidsClassificationService classifier;

    @POST
    @Path("/classify")
    public Response classifyPacket(Packet packet) {
        try {
            NidsPrediction result = classifier.classify(packet);
            return Response.ok(result).build();
        } catch (Exception e) {
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity(Map.of(
                            "error", "Classification failed",
                            "message", e.getMessage(),
                            "hint", "Ensure the Python inference server is running: python api.py"
                    ))
                    .build();
        }
    }

    @POST
    @Path("/classify/batch")
    public Response classifyBatch(List<Packet> packets) {
        try {
            List<NidsPrediction> results = classifier.classifyBatch(packets);
            return Response.ok(results).build();
        } catch (Exception e) {
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity(Map.of(
                            "error", "Batch classification failed",
                            "message", e.getMessage()
                    ))
                    .build();
        }
    }

    @GET
    @Path("/health")
    public Response health() {
        boolean healthy = classifier.isModelServerHealthy();
        Map<String, Object> status = Map.of(
                "quarkus", "ok",
                "python_model_server", healthy ? "ok" : "unreachable"
        );
        return Response.ok(status).build();
    }
}
