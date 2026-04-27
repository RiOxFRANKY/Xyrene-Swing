package com.ibm.developer.model;

import java.time.Instant;

/**
 * Represents a network packet or flow to be processed.
 */
public class Packet {
    private String id;
    private String sourceIp;
    private String destinationIp;
    private int sourcePort;
    private int destinationPort;
    private String protocol;
    private long payloadSize;
    private long headerLength;
    private Instant timestamp;

    // TCP Flags
    private boolean finFlag;
    private boolean synFlag;
    private boolean rstFlag;
    private boolean pshFlag;
    private boolean ackFlag;
    private boolean urgFlag;
    private boolean cweFlag;
    private boolean eceFlag;

    public Packet() {
        this.timestamp = Instant.now();
    }

    public Packet(String id, String sourceIp, String destinationIp, int sourcePort, int destinationPort, String protocol, long payloadSize, long headerLength) {
        this.id = id;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.payloadSize = payloadSize;
        this.headerLength = headerLength;
        this.timestamp = Instant.now();
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getDestinationIp() { return destinationIp; }
    public void setDestinationIp(String destinationIp) { this.destinationIp = destinationIp; }

    public int getSourcePort() { return sourcePort; }
    public void setSourcePort(int sourcePort) { this.sourcePort = sourcePort; }

    public int getDestinationPort() { return destinationPort; }
    public void setDestinationPort(int destinationPort) { this.destinationPort = destinationPort; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public long getPayloadSize() { return payloadSize; }
    public void setPayloadSize(long payloadSize) { this.payloadSize = payloadSize; }

    public long getHeaderLength() { return headerLength; }
    public void setHeaderLength(long headerLength) { this.headerLength = headerLength; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public boolean isFinFlag() { return finFlag; }
    public void setFinFlag(boolean finFlag) { this.finFlag = finFlag; }

    public boolean isSynFlag() { return synFlag; }
    public void setSynFlag(boolean synFlag) { this.synFlag = synFlag; }

    public boolean isRstFlag() { return rstFlag; }
    public void setRstFlag(boolean rstFlag) { this.rstFlag = rstFlag; }

    public boolean isPshFlag() { return pshFlag; }
    public void setPshFlag(boolean pshFlag) { this.pshFlag = pshFlag; }

    public boolean isAckFlag() { return ackFlag; }
    public void setAckFlag(boolean ackFlag) { this.ackFlag = ackFlag; }

    public boolean isUrgFlag() { return urgFlag; }
    public void setUrgFlag(boolean urgFlag) { this.urgFlag = urgFlag; }

    public boolean isCweFlag() { return cweFlag; }
    public void setCweFlag(boolean cweFlag) { this.cweFlag = cweFlag; }

    public boolean isEceFlag() { return eceFlag; }
    public void setEceFlag(boolean eceFlag) { this.eceFlag = eceFlag; }

    @Override
    public String toString() {
        return "Packet{" +
                "id='" + id + '\'' +
                ", sourceIp='" + sourceIp + '\'' +
                ", destinationIp='" + destinationIp + '\'' +
                ", protocol='" + protocol + '\'' +
                ", payloadSize=" + payloadSize +
                '}';
    }
}
