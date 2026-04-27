package com.ibm.developer.model;

import java.time.Instant;
import java.time.Duration;

/**
 * Tracks running statistics for an active flow using Welford's online algorithm
 * to calculate mean and standard deviation without storing arrays of values.
 */
public class FlowState {
    
    // Core Timestamps
    private Instant firstPacketTime;
    private Instant lastPacketTime;

    // Totals
    private long totFwPkts = 0;
    private long totBwPkts = 0;
    private long totLFwPkt = 0;
    private long totLBwPkt = 0;

    // Fw Size Stats
    private long fwPktLMax = Long.MIN_VALUE;
    private long fwPktLMin = Long.MAX_VALUE;
    private double fwPktLMean = 0;
    private double fwPktLM2 = 0; // for variance

    // Bw Size Stats
    private long bwPktLMax = Long.MIN_VALUE;
    private long bwPktLMin = Long.MAX_VALUE;
    private double bwPktLMean = 0;
    private double bwPktLM2 = 0; // for variance

    // IAT (Inter-Arrival Time) Stats (Global, Fw, Bw)
    private Instant lastFwTime;
    private Instant lastBwTime;

    private long flIatMax = Long.MIN_VALUE;
    private long flIatMin = Long.MAX_VALUE;
    private double flIatMean = 0;
    private double flIatM2 = 0;

    private long fwIatTot = 0;
    private long fwIatMax = Long.MIN_VALUE;
    private long fwIatMin = Long.MAX_VALUE;
    private double fwIatMean = 0;
    private double fwIatM2 = 0;

    private long bwIatTot = 0;
    private long bwIatMax = Long.MIN_VALUE;
    private long bwIatMin = Long.MAX_VALUE;
    private double bwIatMean = 0;
    private double bwIatM2 = 0;

    // Flags
    private long finCnt = 0;
    private long synCnt = 0;
    private long rstCnt = 0;
    private long pshCnt = 0;
    private long ackCnt = 0;
    private long urgCnt = 0;
    private long cweCnt = 0;
    private long eceCnt = 0;

    private long fwPshFlag = 0;
    private long bwPshFlag = 0;
    private long fwUrgFlag = 0;
    private long bwUrgFlag = 0;

    // Header Lengths
    private long fwHdrLen = 0;
    private long bwHdrLen = 0;

    public void addPacket(Packet packet, boolean isForward) {
        Instant now = packet.getTimestamp();
        long size = packet.getPayloadSize();

        if (firstPacketTime == null) {
            firstPacketTime = now;
        }

        if (lastPacketTime != null) {
            long iat = Duration.between(lastPacketTime, now).toNanos() / 1000; // microseconds
            updateWelford(iat, totFwPkts + totBwPkts + 1, false, false, true);
        }
        lastPacketTime = now;

        updateFlags(packet, isForward);

        if (isForward) {
            totFwPkts++;
            totLFwPkt += size;
            fwHdrLen += packet.getHeaderLength();

            fwPktLMax = Math.max(fwPktLMax, size);
            fwPktLMin = Math.min(fwPktLMin, size);
            updateWelfordSize(size, totFwPkts, true);

            if (lastFwTime != null) {
                long iat = Duration.between(lastFwTime, now).toNanos() / 1000;
                fwIatTot += iat;
                updateWelford(iat, totFwPkts - 1, true, false, false);
            }
            lastFwTime = now;
        } else {
            totBwPkts++;
            totLBwPkt += size;
            bwHdrLen += packet.getHeaderLength();

            bwPktLMax = Math.max(bwPktLMax, size);
            bwPktLMin = Math.min(bwPktLMin, size);
            updateWelfordSize(size, totBwPkts, false);

            if (lastBwTime != null) {
                long iat = Duration.between(lastBwTime, now).toNanos() / 1000;
                bwIatTot += iat;
                updateWelford(iat, totBwPkts - 1, false, true, false);
            }
            lastBwTime = now;
        }
    }

    private void updateFlags(Packet p, boolean isFw) {
        if (p.isFinFlag()) finCnt++;
        if (p.isSynFlag()) synCnt++;
        if (p.isRstFlag()) rstCnt++;
        if (p.isPshFlag()) {
            pshCnt++;
            if (isFw) fwPshFlag++; else bwPshFlag++;
        }
        if (p.isAckFlag()) ackCnt++;
        if (p.isUrgFlag()) {
            urgCnt++;
            if (isFw) fwUrgFlag++; else bwUrgFlag++;
        }
        if (p.isCweFlag()) cweCnt++;
        if (p.isEceFlag()) eceCnt++;
    }

    private void updateWelfordSize(long size, long count, boolean isFw) {
        if (isFw) {
            double delta = size - fwPktLMean;
            fwPktLMean += delta / count;
            fwPktLM2 += delta * (size - fwPktLMean);
        } else {
            double delta = size - bwPktLMean;
            bwPktLMean += delta / count;
            bwPktLM2 += delta * (size - bwPktLMean);
        }
    }

    private void updateWelford(long val, long count, boolean isFwIat, boolean isBwIat, boolean isGlobalIat) {
        if (isGlobalIat) {
            flIatMax = Math.max(flIatMax, val);
            flIatMin = Math.min(flIatMin, val);
            double delta = val - flIatMean;
            flIatMean += delta / count;
            flIatM2 += delta * (val - flIatMean);
        } else if (isFwIat) {
            fwIatMax = Math.max(fwIatMax, val);
            fwIatMin = Math.min(fwIatMin, val);
            double delta = val - fwIatMean;
            fwIatMean += delta / count;
            fwIatM2 += delta * (val - fwIatMean);
        } else if (isBwIat) {
            bwIatMax = Math.max(bwIatMax, val);
            bwIatMin = Math.min(bwIatMin, val);
            double delta = val - bwIatMean;
            bwIatMean += delta / count;
            bwIatM2 += delta * (val - bwIatMean);
        }
    }

    // Export feature object
    public CicFlowFeatures exportFeatures() {
        return new CicFlowFeatures(this);
    }

    // Getters for CicFlowFeatures to consume
    public Instant getFirstPacketTime() { return firstPacketTime; }
    public Instant getLastPacketTime() { return lastPacketTime; }
    public long getTotFwPkts() { return totFwPkts; }
    public long getTotBwPkts() { return totBwPkts; }
    public long getTotLFwPkt() { return totLFwPkt; }
    public long getTotLBwPkt() { return totLBwPkt; }
    public long getFwPktLMax() { return fwPktLMax == Long.MIN_VALUE ? 0 : fwPktLMax; }
    public long getFwPktLMin() { return fwPktLMin == Long.MAX_VALUE ? 0 : fwPktLMin; }
    public double getFwPktLMean() { return fwPktLMean; }
    public double getFwPktLStd() { return totFwPkts > 1 ? Math.sqrt(fwPktLM2 / (totFwPkts - 1)) : 0; }
    public long getBwPktLMax() { return bwPktLMax == Long.MIN_VALUE ? 0 : bwPktLMax; }
    public long getBwPktLMin() { return bwPktLMin == Long.MAX_VALUE ? 0 : bwPktLMin; }
    public double getBwPktLMean() { return bwPktLMean; }
    public double getBwPktLStd() { return totBwPkts > 1 ? Math.sqrt(bwPktLM2 / (totBwPkts - 1)) : 0; }
    public long getFlIatMax() { return flIatMax == Long.MIN_VALUE ? 0 : flIatMax; }
    public long getFlIatMin() { return flIatMin == Long.MAX_VALUE ? 0 : flIatMin; }
    public double getFlIatMean() { return flIatMean; }
    public double getFlIatStd() { long t = totFwPkts + totBwPkts; return t > 2 ? Math.sqrt(flIatM2 / (t - 2)) : 0; }
    public long getFwIatTot() { return fwIatTot; }
    public long getFwIatMax() { return fwIatMax == Long.MIN_VALUE ? 0 : fwIatMax; }
    public long getFwIatMin() { return fwIatMin == Long.MAX_VALUE ? 0 : fwIatMin; }
    public double getFwIatMean() { return fwIatMean; }
    public double getFwIatStd() { return totFwPkts > 2 ? Math.sqrt(fwIatM2 / (totFwPkts - 2)) : 0; }
    public long getBwIatTot() { return bwIatTot; }
    public long getBwIatMax() { return bwIatMax == Long.MIN_VALUE ? 0 : bwIatMax; }
    public long getBwIatMin() { return bwIatMin == Long.MAX_VALUE ? 0 : bwIatMin; }
    public double getBwIatMean() { return bwIatMean; }
    public double getBwIatStd() { return totBwPkts > 2 ? Math.sqrt(bwIatM2 / (totBwPkts - 2)) : 0; }
    public long getFinCnt() { return finCnt; }
    public long getSynCnt() { return synCnt; }
    public long getRstCnt() { return rstCnt; }
    public long getPshCnt() { return pshCnt; }
    public long getAckCnt() { return ackCnt; }
    public long getUrgCnt() { return urgCnt; }
    public long getCweCnt() { return cweCnt; }
    public long getEceCnt() { return eceCnt; }
    public long getFwPshFlag() { return fwPshFlag; }
    public long getBwPshFlag() { return bwPshFlag; }
    public long getFwUrgFlag() { return fwUrgFlag; }
    public long getBwUrgFlag() { return bwUrgFlag; }
    public long getFwHdrLen() { return fwHdrLen; }
    public long getBwHdrLen() { return bwHdrLen; }
}
