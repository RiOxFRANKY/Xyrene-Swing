package com.ibm.developer.interceptor;

import com.ibm.developer.model.CicFlowFeatures;
import com.ibm.developer.model.FlowKey;
import com.ibm.developer.model.FlowState;
import com.ibm.developer.model.Packet;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Interceptor that aggregates packets into flows and calculates CIC-BoT-IoT features.
 */
@ApplicationScoped
public class CicFeatureExtractorInterceptor extends BasePacketInterceptor {

    // Thread-safe map of active flows. In production, this would have an eviction/expiry policy.
    private final Map<FlowKey, FlowState> activeFlows = new ConcurrentHashMap<>();

    @Override
    protected boolean processPacket(Packet packet) {
        
        // 1. Determine Flow Key (always src -> dst for forward)
        FlowKey fwdKey = new FlowKey(packet.getSourceIp(), packet.getDestinationIp(), 
                                     packet.getSourcePort(), packet.getDestinationPort(), 
                                     packet.getProtocol());
        FlowKey bwdKey = fwdKey.reversed();

        boolean isForward = true;
        FlowState state;

        // 2. Lookup or create Flow State
        if (activeFlows.containsKey(fwdKey)) {
            state = activeFlows.get(fwdKey);
        } else if (activeFlows.containsKey(bwdKey)) {
            state = activeFlows.get(bwdKey);
            isForward = false;
        } else {
            state = new FlowState();
            activeFlows.put(fwdKey, state);
        }

        // 3. Update State using Welford's online algorithm
        state.addPacket(packet, isForward);

        // 4. (Optional) If FIN flag is set, the flow is ending. We could export features here.
        if (packet.isFinFlag()) {
            CicFlowFeatures finalFeatures = state.exportFeatures();
            logger.infov("Flow {0} completed. Extracted {1} backward packets, Duration: {2}ms", 
                    fwdKey.hashCode(), finalFeatures.tot_bw_pk, finalFeatures.fl_dur / 1000);
            
            // In a real system, you'd send `finalFeatures` to a Kafka topic or directly to your ML model
            activeFlows.remove(fwdKey);
            activeFlows.remove(bwdKey);
        }

        return true; // Always allow packet to continue through the chain
    }

    @Override
    public int getPriority() {
        return 30; // Run after basic security and logging
    }
}
