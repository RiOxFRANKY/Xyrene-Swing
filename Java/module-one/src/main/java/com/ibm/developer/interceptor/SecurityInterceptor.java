package com.ibm.developer.interceptor;

import com.ibm.developer.model.Packet;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class SecurityInterceptor extends BasePacketInterceptor {

    // Simple mockup for known malicious IPs
    private static final String[] BLOCKED_IPS = {"192.168.1.100", "10.0.0.55"};

    @Override
    protected boolean processPacket(Packet packet) {
        
        // 1. IP Blacklist Check
        for (String blockedIp : BLOCKED_IPS) {
            if (blockedIp.equals(packet.getSourceIp())) {
                logger.warnv("SECURITY ALERT: Packet from blocked IP dropped -> {0}", packet.getSourceIp());
                return false;
            }
        }

        // 2. DDoS / Large Payload Check
        if (packet.getPayloadSize() > 65535) { // e.g. exceeding max TCP/UDP packet size loosely
            logger.warnv("SECURITY ALERT: Dropping abnormally large packet -> Size: {0}", packet.getPayloadSize());
            return false;
        }

        // 3. Port Scan Signature (Mock)
        if (packet.getDestinationPort() == 22 || packet.getDestinationPort() == 3389) {
            logger.infov("SECURITY AUDIT: Sensitive port targeted ({0})", packet.getDestinationPort());
            // We might just audit this but not drop it immediately
        }

        return true;
    }

    @Override
    public int getPriority() {
        return 20; // Run after logging
    }
}
