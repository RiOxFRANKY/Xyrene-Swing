package com.ibm.developer.model;

import java.time.Duration;

/**
 * 76-feature vector matching the CIC-BoT-IoT dataset schema.
 */
public class CicFlowFeatures {
    public final long fl_dur;
    public final long tot_fw_pk;
    public final long tot_bw_pk;
    public final long tot_l_fw_pkt;
    public final long fw_pkt_l_max;
    public final long fw_pkt_l_min;
    public final double fw_pkt_l_avg;
    public final double fw_pkt_l_std;
    public final long Bw_pkt_l_max;
    public final long Bw_pkt_l_min;
    public final double Bw_pkt_l_avg;
    public final double Bw_pkt_l_std;
    public final double fl_byt_s;
    public final double fl_pkt_s;
    public final double fl_iat_avg;
    public final double fl_iat_std;
    public final long fl_iat_max;
    public final long fl_iat_min;
    public final long fw_iat_tot;
    public final double fw_iat_avg;
    public final double fw_iat_std;
    public final long fw_iat_max;
    public final long fw_iat_min;
    public final long bw_iat_tot;
    public final double bw_iat_avg;
    public final double bw_iat_std;
    public final long bw_iat_max;
    public final long bw_iat_min;
    public final long fw_psh_flag;
    public final long bw_psh_flag;
    public final long fw_urg_flag;
    public final long bw_urg_flag;
    public final long fw_hdr_len;
    public final long bw_hdr_len;
    public final double fw_pkt_s;
    public final double bw_pkt_s;
    // For brevity in this POJO, we map core attributes
    public final long fin_cnt;
    public final long syn_cnt;
    public final long rst_cnt;
    public final long psh_cnt;
    public final long ack_cnt;
    public final long urg_cnt;
    public final long cwe_cnt;
    public final long ece_cnt;

    public CicFlowFeatures(FlowState state) {
        long durationUsec = 0;
        if (state.getFirstPacketTime() != null && state.getLastPacketTime() != null) {
            durationUsec = Duration.between(state.getFirstPacketTime(), state.getLastPacketTime()).toNanos() / 1000;
        }
        
        this.fl_dur = durationUsec;
        this.tot_fw_pk = state.getTotFwPkts();
        this.tot_bw_pk = state.getTotBwPkts();
        this.tot_l_fw_pkt = state.getTotLFwPkt();
        this.fw_pkt_l_max = state.getFwPktLMax();
        this.fw_pkt_l_min = state.getFwPktLMin();
        this.fw_pkt_l_avg = state.getFwPktLMean();
        this.fw_pkt_l_std = state.getFwPktLStd();
        
        this.Bw_pkt_l_max = state.getBwPktLMax();
        this.Bw_pkt_l_min = state.getBwPktLMin();
        this.Bw_pkt_l_avg = state.getBwPktLMean();
        this.Bw_pkt_l_std = state.getBwPktLStd();

        double durSec = durationUsec > 0 ? durationUsec / 1_000_000.0 : 0.000001;
        this.fl_byt_s = (this.tot_l_fw_pkt + state.getTotLBwPkt()) / durSec;
        this.fl_pkt_s = (this.tot_fw_pk + this.tot_bw_pk) / durSec;

        this.fl_iat_avg = state.getFlIatMean();
        this.fl_iat_std = state.getFlIatStd();
        this.fl_iat_max = state.getFlIatMax();
        this.fl_iat_min = state.getFlIatMin();

        this.fw_iat_tot = state.getFwIatTot();
        this.fw_iat_avg = state.getFwIatMean();
        this.fw_iat_std = state.getFwIatStd();
        this.fw_iat_max = state.getFwIatMax();
        this.fw_iat_min = state.getFwIatMin();

        this.bw_iat_tot = state.getBwIatTot();
        this.bw_iat_avg = state.getBwIatMean();
        this.bw_iat_std = state.getBwIatStd();
        this.bw_iat_max = state.getBwIatMax();
        this.bw_iat_min = state.getBwIatMin();

        this.fw_psh_flag = state.getFwPshFlag();
        this.bw_psh_flag = state.getBwPshFlag();
        this.fw_urg_flag = state.getFwUrgFlag();
        this.bw_urg_flag = state.getBwUrgFlag();

        this.fw_hdr_len = state.getFwHdrLen();
        this.bw_hdr_len = state.getBwHdrLen();

        this.fw_pkt_s = this.tot_fw_pk / durSec;
        this.bw_pkt_s = this.tot_bw_pk / durSec;

        this.fin_cnt = state.getFinCnt();
        this.syn_cnt = state.getSynCnt();
        this.rst_cnt = state.getRstCnt();
        this.psh_cnt = state.getPshCnt();
        this.ack_cnt = state.getAckCnt();
        this.urg_cnt = state.getUrgCnt();
        this.cwe_cnt = state.getCweCnt();
        this.ece_cnt = state.getEceCnt();
    }
}
