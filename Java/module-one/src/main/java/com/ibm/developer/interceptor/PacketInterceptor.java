package com.ibm.developer.interceptor;

import com.ibm.developer.model.Packet;

/**
 * Interface defining the contract for packet interceptors.
 * Implementing classes can analyze, log, or drop packets.
 */
public interface PacketInterceptor {
    
    /**
     * Inspects the given packet.
     * 
     * @param packet The packet to process.
     * @return true if the packet should continue to the next interceptor, false if it should be dropped.
     */
    boolean intercept(Packet packet);
    
    /**
     * @return Priority order for execution. Lower number = earlier execution.
     */
    int getPriority();
}
