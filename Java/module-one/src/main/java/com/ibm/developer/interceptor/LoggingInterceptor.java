package com.ibm.developer.interceptor;

import com.ibm.developer.model.Packet;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class LoggingInterceptor extends BasePacketInterceptor {

    @Override
    protected boolean processPacket(Packet packet) {
        logger.infov("PACKET INTERCEPTED: [ID: {0}] {1}:{2} -> {3}:{4} | Protocol: {5} | Size: {6} bytes",
                packet.getId(),
                packet.getSourceIp(), packet.getSourcePort(),
                packet.getDestinationIp(), packet.getDestinationPort(),
                packet.getProtocol(),
                packet.getPayloadSize());
        
        // Always allow the packet to pass through the logging layer
        return true;
    }

    @Override
    public int getPriority() {
        return 10; // High priority, run first
    }
}
