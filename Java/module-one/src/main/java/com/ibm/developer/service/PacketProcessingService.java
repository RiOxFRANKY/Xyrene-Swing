package com.ibm.developer.service;

import com.ibm.developer.interceptor.PacketInterceptor;
import com.ibm.developer.model.Packet;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@ApplicationScoped
public class PacketProcessingService {

    private static final Logger logger = Logger.getLogger(PacketProcessingService.class);
    
    private final List<PacketInterceptor> interceptors = new ArrayList<>();

    // Inject all available interceptors automatically using CDI
    @Inject
    public PacketProcessingService(Instance<PacketInterceptor> interceptorInstances) {
        for (PacketInterceptor interceptor : interceptorInstances) {
            interceptors.add(interceptor);
        }
        // Sort interceptors by priority (lower number runs first)
        interceptors.sort(Comparator.comparingInt(PacketInterceptor::getPriority));
        
        logger.infov("Initialized PacketProcessingService with {0} interceptors", interceptors.size());
    }

    /**
     * Feeds the packet through the chain of interceptors.
     * 
     * @param packet The packet to process.
     * @return true if it passed all interceptors, false if any interceptor dropped it.
     */
    public boolean processPacket(Packet packet) {
        for (PacketInterceptor interceptor : interceptors) {
            boolean allowed = interceptor.intercept(packet);
            if (!allowed) {
                logger.warnv("Packet {0} was dropped by {1}", packet.getId(), interceptor.getClass().getSimpleName());
                return false; // Stop the chain
            }
        }
        
        logger.infov("Packet {0} passed all interceptors successfully.", packet.getId());
        return true;
    }
}
