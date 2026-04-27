package com.ibm.developer.model;

import java.util.Objects;

/**
 * Unique identifier for a network flow (5-tuple).
 */
public class FlowKey {
    private final String sourceIp;
    private final String destinationIp;
    private final int sourcePort;
    private final int destinationPort;
    private final String protocol;

    public FlowKey(String sourceIp, String destinationIp, int sourcePort, int destinationPort, String protocol) {
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
    }

    public FlowKey reversed() {
        return new FlowKey(destinationIp, sourceIp, destinationPort, sourcePort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FlowKey flowKey = (FlowKey) o;
        return sourcePort == flowKey.sourcePort &&
               destinationPort == flowKey.destinationPort &&
               Objects.equals(sourceIp, flowKey.sourceIp) &&
               Objects.equals(destinationIp, flowKey.destinationIp) &&
               Objects.equals(protocol, flowKey.protocol);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceIp, destinationIp, sourcePort, destinationPort, protocol);
    }
}
