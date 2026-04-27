package com.ibm.developer.model;

/**
 * The 8 engineered features required by the Keras NIDS model (nids_model.keras).
 * These are derived from CIC-FlowMeter flow-level statistics tracked by {@link FlowState}.
 *
 * Feature mapping:
 *   packet_size       = average packet size across the entire flow
 *   packets_per_sec   = total packets / flow duration (seconds)
 *   bytes_sent        = total bytes in forward direction
 *   bytes_received    = total bytes in backward direction
 *   connection_duration = flow duration in microseconds
 *   unique_ports      = destination port (used as proxy for port diversity)
 *   failed_logins     = RST flag count (rejected/failed connections)
 *   syn_ratio         = SYN / (SYN + ACK + epsilon) to detect SYN flood patterns
 */
public class NidsFeatures {

    private final double packetSize;
    private final double packetsPerSec;
    private final double bytesSent;
    private final double bytesReceived;
    private final double connectionDuration;
    private final double uniquePorts;
    private final double failedLogins;
    private final double synRatio;

    public NidsFeatures(double packetSize, double packetsPerSec, double bytesSent,
                        double bytesReceived, double connectionDuration,
                        double uniquePorts, double failedLogins, double synRatio) {
        this.packetSize = packetSize;
        this.packetsPerSec = packetsPerSec;
        this.bytesSent = bytesSent;
        this.bytesReceived = bytesReceived;
        this.connectionDuration = connectionDuration;
        this.uniquePorts = uniquePorts;
        this.failedLogins = failedLogins;
        this.synRatio = synRatio;
    }

    /**
     * Returns the 8 features as a double array in the exact order
     * the Keras model and MinMaxScaler expect:
     * [packet_size, packets_per_sec, bytes_sent, bytes_received,
     *  connection_duration, unique_ports, failed_logins, syn_ratio]
     */
    public double[] toArray() {
        return new double[]{
                packetSize, packetsPerSec, bytesSent, bytesReceived,
                connectionDuration, uniquePorts, failedLogins, synRatio
        };
    }

    // --- Getters ---
    public double getPacketSize() { return packetSize; }
    public double getPacketsPerSec() { return packetsPerSec; }
    public double getBytesSent() { return bytesSent; }
    public double getBytesReceived() { return bytesReceived; }
    public double getConnectionDuration() { return connectionDuration; }
    public double getUniquePorts() { return uniquePorts; }
    public double getFailedLogins() { return failedLogins; }
    public double getSynRatio() { return synRatio; }

    @Override
    public String toString() {
        return String.format(
                "NidsFeatures{packetSize=%.2f, pkt/s=%.2f, sent=%.0f, recv=%.0f, dur=%.0f, ports=%.0f, rst=%.0f, synR=%.4f}",
                packetSize, packetsPerSec, bytesSent, bytesReceived,
                connectionDuration, uniquePorts, failedLogins, synRatio
        );
    }
}
