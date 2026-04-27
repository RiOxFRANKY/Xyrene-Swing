package com.ibm.developer.service;

import com.ibm.developer.model.FlowKey;
import com.ibm.developer.model.FlowState;
import com.ibm.developer.model.NidsFeatures;
import com.ibm.developer.model.Packet;
import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Extracts the 8 NIDS features from live network packets by tracking per-flow state.
 *
 * Each packet is assigned to a flow (5-tuple: srcIP, dstIP, srcPort, dstPort, protocol).
 * The service maintains a {@link FlowState} for every active flow and derives
 * the 8 engineered features the Keras model needs for classification.
 *
 * Feature derivation from FlowState:
 *   packet_size       = total_bytes / total_packets (average packet size)
 *   packets_per_sec   = total_packets / duration_seconds
 *   bytes_sent        = total forward payload bytes
 *   bytes_received    = total backward payload bytes
 *   connection_duration = flow duration in microseconds
 *   unique_ports      = destination port of the flow
 *   failed_logins     = RST flag count
 *   syn_ratio         = SYN_count / (SYN_count + ACK_count + 1e-9)
 */
@ApplicationScoped
public class FeatureExtractorService {

    private static final Logger logger = Logger.getLogger(FeatureExtractorService.class);

    /**
     * Active flow table. Keyed by the forward FlowKey; packets in the reverse
     * direction are matched via {@link FlowKey#reversed()}.
     */
    private final ConcurrentHashMap<FlowKey, FlowState> flowTable = new ConcurrentHashMap<>();

    /**
     * Stores the destination port for each flow (used as the "unique_ports" feature).
     */
    private final ConcurrentHashMap<FlowKey, Integer> flowDstPort = new ConcurrentHashMap<>();

    /**
     * Processes a raw packet: updates the corresponding flow state and returns
     * the current 8-feature snapshot for that flow.
     *
     * @param packet The incoming network packet.
     * @return The 8 NIDS features computed from the flow this packet belongs to.
     */
    public NidsFeatures extractFeatures(Packet packet) {
        FlowKey fwdKey = new FlowKey(
                packet.getSourceIp(), packet.getDestinationIp(),
                packet.getSourcePort(), packet.getDestinationPort(),
                packet.getProtocol()
        );
        FlowKey revKey = fwdKey.reversed();

        // Determine direction: if we already have a flow keyed by the reverse, this is backward
        boolean isForward;
        FlowKey activeKey;

        if (flowTable.containsKey(fwdKey)) {
            activeKey = fwdKey;
            isForward = true;
        } else if (flowTable.containsKey(revKey)) {
            activeKey = revKey;
            isForward = false;
        } else {
            // New flow — register with forward key
            activeKey = fwdKey;
            isForward = true;
            flowTable.put(activeKey, new FlowState());
            flowDstPort.put(activeKey, packet.getDestinationPort());
        }

        FlowState state = flowTable.get(activeKey);
        state.addPacket(packet, isForward);

        return deriveFeatures(state, flowDstPort.getOrDefault(activeKey, 0));
    }

    /**
     * Derives the 8 Keras features from a FlowState snapshot.
     */
    private NidsFeatures deriveFeatures(FlowState state, int dstPort) {
        long totalPkts = state.getTotFwPkts() + state.getTotBwPkts();
        long totalBytes = state.getTotLFwPkt() + state.getTotLBwPkt();

        // Duration in microseconds
        double durationUsec = 0;
        if (state.getFirstPacketTime() != null && state.getLastPacketTime() != null) {
            durationUsec = java.time.Duration.between(
                    state.getFirstPacketTime(), state.getLastPacketTime()
            ).toNanos() / 1000.0;
        }

        // 1. packet_size = average packet size
        double packetSize = totalPkts > 0 ? (double) totalBytes / totalPkts : 0.0;

        // 2. packets_per_sec = total packets / duration in seconds
        double durationSec = durationUsec > 0 ? durationUsec / 1_000_000.0 : 0.000001;
        double packetsPerSec = totalPkts / durationSec;

        // 3. bytes_sent = total forward payload
        double bytesSent = state.getTotLFwPkt();

        // 4. bytes_received = total backward payload
        double bytesReceived = state.getTotLBwPkt();

        // 5. connection_duration = flow duration (microseconds)
        double connectionDuration = durationUsec;

        // 6. unique_ports = destination port
        double uniquePorts = dstPort;

        // 7. failed_logins = RST flag count
        double failedLogins = state.getRstCnt();

        // 8. syn_ratio = SYN / (SYN + ACK + epsilon)
        double syn = state.getSynCnt();
        double ack = state.getAckCnt();
        double synRatio = syn / (syn + ack + 1e-9);

        return new NidsFeatures(
                packetSize, packetsPerSec, bytesSent, bytesReceived,
                connectionDuration, uniquePorts, failedLogins, synRatio
        );
    }

    /**
     * Evicts a completed flow from the table (e.g., after FIN/RST or timeout).
     */
    public void evictFlow(FlowKey key) {
        flowTable.remove(key);
        flowDstPort.remove(key);
        logger.debugv("Evicted flow: {0}", key);
    }

    /**
     * Returns the current number of active flows being tracked.
     */
    public int getActiveFlowCount() {
        return flowTable.size();
    }
}
