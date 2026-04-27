package com.ibm.developer.interceptor;

import com.ibm.developer.model.Packet;
import org.jboss.logging.Logger;

/**
 * Abstract class providing common utilities for all packet interceptors.
 */
public abstract class BasePacketInterceptor implements PacketInterceptor {

    protected final Logger logger = Logger.getLogger(this.getClass());

    @Override
    public boolean intercept(Packet packet) {
        if (packet == null) {
            logger.warn("Received null packet. Dropping.");
            return false;
        }

        long startTime = System.currentTimeMillis();
        boolean allow = processPacket(packet);
        long duration = System.currentTimeMillis() - startTime;

        logger.debugv("Interceptor {0} processed packet {1} in {2}ms. Action: {3}", 
                this.getClass().getSimpleName(), packet.getId(), duration, allow ? "ALLOW" : "DROP");

        return allow;
    }

    /**
     * Core logic to be implemented by concrete interceptors.
     */
    protected abstract boolean processPacket(Packet packet);
}
