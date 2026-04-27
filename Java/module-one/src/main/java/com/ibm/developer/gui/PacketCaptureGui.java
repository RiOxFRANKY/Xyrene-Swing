package com.ibm.developer.gui;

import com.formdev.flatlaf.FlatDarkLaf;
import com.ibm.developer.model.FlowKey;
import com.ibm.developer.model.FlowState;
import com.ibm.developer.model.NidsFeatures;
import com.ibm.developer.model.Packet;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class PacketCaptureGui extends JFrame {

    // ── Colors (Burp-inspired orange accent on dark) ─────────────────────────
    private static final Color ACCENT       = new Color(255, 102, 51);    // Burp orange
    private static final Color ACCENT_DIM   = new Color(180, 80, 20);
    private static final Color GREEN        = new Color(40, 200, 100);
    private static final Color RED          = new Color(240, 60, 70);
    private static final Color YELLOW       = new Color(240, 200, 50);
    private static final Color BG_CARD      = new Color(40, 42, 54);
    private static final Color BG_DARKER    = new Color(30, 31, 40);
    private static final Color FG           = new Color(210, 215, 225);
    private static final Color FG_DIM       = new Color(130, 135, 150);
    private static final DateTimeFormatter TF = DateTimeFormatter.ofPattern("HH:mm:ss");

    // ── State ────────────────────────────────────────────────────────────────
    private PcapHandle handle;
    private Thread captureThread;
    private volatile boolean capturing = false;
    private final ConcurrentHashMap<String, int[]> ipStats = new ConcurrentHashMap<>();
    private final AtomicInteger nextRow = new AtomicInteger(0);
    private final ConcurrentHashMap<FlowKey, FlowState> flowTable = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<FlowKey, Integer> flowDstPort = new ConcurrentHashMap<>();
    private volatile int totalPkts, totalBenign, totalMalicious;
    private final java.util.List<String[]> eventLog = java.util.Collections.synchronizedList(new ArrayList<>());
    private static final String API = "http://localhost:8000/predict";

    private static class ClassifyTask {
        String srcIp;
        NidsFeatures features;
        ClassifyTask(String srcIp, NidsFeatures features) { this.srcIp = srcIp; this.features = features; }
    }
    private final ConcurrentLinkedQueue<ClassifyTask> classifyQueue = new ConcurrentLinkedQueue<>();
    private Thread batcherThread;

    // ── UI Components ────────────────────────────────────────────────────────
    private DefaultTableModel trafficModel, logModel;
    private JLabel lblTotal, lblBenign, lblMalicious, lblIps, lblStatus;
    private JButton btnStart, btnStop;
    private JComboBox<String> ifCombo;
    private JProgressBar threatBar;

    public PacketCaptureGui() {
        super("Xyrene NIDS");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1050, 680);
        setMinimumSize(new Dimension(800, 500));
        setLocationRelativeTo(null);

        // ── Main layout ──────────────────────────────────────────────────────
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG_DARKER);

        // Top brand bar
        root.add(createBrandBar(), BorderLayout.NORTH);

        // Tabbed pane
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(new Font("Segoe UI", Font.BOLD, 13));
        tabs.setForeground(FG);
        tabs.addTab("\u2302  Dashboard", createDashboard());
        tabs.addTab("\u21C4  Traffic", createTrafficPanel());
        tabs.addTab("\u26A0  Event Log", createLogPanel());
        root.add(tabs, BorderLayout.CENTER);

        // Status bar
        root.add(createStatusBar(), BorderLayout.SOUTH);

        setContentPane(root);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  BRAND BAR
    // ═══════════════════════════════════════════════════════════════════════════
    private JPanel createBrandBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(new Color(25, 26, 34));
        bar.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, ACCENT));
        bar.setPreferredSize(new Dimension(0, 44));

        JLabel title = new JLabel("   \u26A1 XYRENE NIDS");
        title.setFont(new Font("Segoe UI", Font.BOLD, 18));
        title.setForeground(ACCENT);
        bar.add(title, BorderLayout.WEST);

        // Controls
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 7));
        controls.setOpaque(false);

        ifCombo = new JComboBox<>();
        ifCombo.setFont(new Font("Consolas", Font.PLAIN, 11));
        ifCombo.setPreferredSize(new Dimension(260, 28));
        loadInterfaces();
        controls.add(ifCombo);

        btnStart = makeBtn("\u25B6 Start", GREEN);
        btnStart.addActionListener(e -> startCapture());
        controls.add(btnStart);

        btnStop = makeBtn("\u25A0 Stop", RED);
        btnStop.setEnabled(false);
        btnStop.addActionListener(e -> stopCapture());
        controls.add(btnStop);

        bar.add(controls, BorderLayout.EAST);
        return bar;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  DASHBOARD TAB
    // ═══════════════════════════════════════════════════════════════════════════
    private JPanel createDashboard() {
        JPanel dash = new JPanel(new BorderLayout(0, 12));
        dash.setBackground(BG_DARKER);
        dash.setBorder(new EmptyBorder(16, 20, 16, 20));

        // Stat cards row
        JPanel cards = new JPanel(new GridLayout(1, 4, 14, 0));
        cards.setOpaque(false);

        lblTotal     = new JLabel("0", SwingConstants.CENTER);
        lblBenign    = new JLabel("0", SwingConstants.CENTER);
        lblMalicious = new JLabel("0", SwingConstants.CENTER);
        lblIps       = new JLabel("0", SwingConstants.CENTER);

        cards.add(statCard("TOTAL PACKETS", lblTotal, ACCENT));
        cards.add(statCard("BENIGN", lblBenign, GREEN));
        cards.add(statCard("MALICIOUS", lblMalicious, RED));
        cards.add(statCard("UNIQUE IPs", lblIps, YELLOW));
        dash.add(cards, BorderLayout.NORTH);

        // Threat level bar
        JPanel threatPanel = new JPanel(new BorderLayout(8, 0));
        threatPanel.setOpaque(false);
        threatPanel.setBorder(new EmptyBorder(8, 0, 4, 0));
        JLabel tl = new JLabel("THREAT LEVEL");
        tl.setFont(new Font("Segoe UI", Font.BOLD, 11));
        tl.setForeground(FG_DIM);
        threatPanel.add(tl, BorderLayout.WEST);
        threatBar = new JProgressBar(0, 100);
        threatBar.setValue(0);
        threatBar.setStringPainted(true);
        threatBar.setString("0.0%");
        threatBar.setFont(new Font("Consolas", Font.BOLD, 12));
        threatBar.setForeground(GREEN);
        threatBar.setBackground(BG_CARD);
        threatBar.setPreferredSize(new Dimension(0, 24));
        threatPanel.add(threatBar, BorderLayout.CENTER);
        dash.add(threatPanel, BorderLayout.CENTER);

        // Recent activity (last 8 events)
        JPanel recentPanel = new JPanel(new BorderLayout());
        recentPanel.setOpaque(false);
        recentPanel.setBorder(new EmptyBorder(8, 0, 0, 0));
        JLabel rl = new JLabel("RECENT ACTIVITY");
        rl.setFont(new Font("Segoe UI", Font.BOLD, 11));
        rl.setForeground(FG_DIM);
        rl.setBorder(new EmptyBorder(0, 0, 6, 0));
        recentPanel.add(rl, BorderLayout.NORTH);
        dash.add(recentPanel, BorderLayout.SOUTH);

        return dash;
    }

    private JPanel statCard(String label, JLabel valueLabel, Color accent) {
        JPanel card = new JPanel(new BorderLayout(0, 4)) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(BG_CARD);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14);
                // Top accent line
                g2.setColor(accent);
                g2.fillRoundRect(0, 0, getWidth(), 4, 4, 4);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setBorder(new EmptyBorder(16, 16, 14, 16));

        JLabel lbl = new JLabel(label);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 10));
        lbl.setForeground(FG_DIM);
        card.add(lbl, BorderLayout.NORTH);

        valueLabel.setFont(new Font("Consolas", Font.BOLD, 32));
        valueLabel.setForeground(accent);
        card.add(valueLabel, BorderLayout.CENTER);

        return card;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  TRAFFIC TAB
    // ═══════════════════════════════════════════════════════════════════════════
    private JPanel createTrafficPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARKER);
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        String[] cols = {"Source IP", "Packets", "Benign", "Malicious", "Threat %"};
        trafficModel = new DefaultTableModel(cols, 0) {
            public boolean isCellEditable(int r, int c) { return false; }
            public Class<?> getColumnClass(int c) { return c == 0 ? String.class : c == 4 ? Double.class : Integer.class; }
        };
        JTable table = new JTable(trafficModel);
        table.setRowHeight(28);
        table.setFont(new Font("Consolas", Font.PLAIN, 13));
        table.setGridColor(new Color(50, 52, 65));
        table.setAutoCreateRowSorter(true);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));

        // Cell renderer
        DefaultTableCellRenderer cellR = new DefaultTableCellRenderer() {
            { setHorizontalAlignment(CENTER); }
            public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                int mc = t.convertColumnIndexToModel(c);
                if (!s) {
                    setBackground(BG_DARKER);
                    if (mc == 0) setForeground(ACCENT);
                    else if (mc == 2) setForeground(GREEN);
                    else if (mc == 3) { int val = v != null ? (int)v : 0; setForeground(val > 0 ? RED : FG_DIM); if (val > 0) setBackground(new Color(55, 22, 28)); }
                    else if (mc == 4) { double val = v != null ? (double)v : 0; setForeground(val > 20 ? RED : val > 5 ? YELLOW : GREEN); setText(String.format("%.1f%%", val)); }
                    else setForeground(FG);
                }
                return this;
            }
        };
        for (int i = 0; i < cols.length; i++) table.getColumnModel().getColumn(i).setCellRenderer(cellR);

        JScrollPane sp = new JScrollPane(table);
        sp.setBorder(BorderFactory.createLineBorder(new Color(50, 52, 65)));
        panel.add(sp, BorderLayout.CENTER);

        // Clear button
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottom.setOpaque(false);
        JButton clearBtn = makeBtn("Clear", YELLOW);
        clearBtn.addActionListener(e -> { trafficModel.setRowCount(0); ipStats.clear(); nextRow.set(0); flowTable.clear(); flowDstPort.clear(); totalPkts = totalBenign = totalMalicious = 0; refreshStats(); });
        bottom.add(clearBtn);
        panel.add(bottom, BorderLayout.SOUTH);

        return panel;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  EVENT LOG TAB
    // ═══════════════════════════════════════════════════════════════════════════
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG_DARKER);
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));

        logModel = new DefaultTableModel(new String[]{"Time", "Source IP", "Type", "Details"}, 0) {
            public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable logTable = new JTable(logModel);
        logTable.setRowHeight(26);
        logTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        logTable.setGridColor(new Color(50, 52, 65));

        DefaultTableCellRenderer logR = new DefaultTableCellRenderer() {
            public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, s, f, r, c);
                if (!s) {
                    setBackground(BG_DARKER);
                    String type = (String) logModel.getValueAt(t.convertRowIndexToModel(r), 2);
                    setForeground("ATTACK".equals(type) ? RED : "BENIGN".equals(type) ? GREEN : FG_DIM);
                }
                return this;
            }
        };
        for (int i = 0; i < 4; i++) logTable.getColumnModel().getColumn(i).setCellRenderer(logR);
        logTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        logTable.getColumnModel().getColumn(1).setPreferredWidth(140);
        logTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        logTable.getColumnModel().getColumn(3).setPreferredWidth(400);

        panel.add(new JScrollPane(logTable), BorderLayout.CENTER);
        return panel;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  STATUS BAR
    // ═══════════════════════════════════════════════════════════════════════════
    private JPanel createStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(new Color(25, 26, 34));
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(50, 52, 65)),
                new EmptyBorder(4, 12, 4, 12)));

        lblStatus = new JLabel("\u25CF Idle");
        lblStatus.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        lblStatus.setForeground(FG_DIM);
        bar.add(lblStatus, BorderLayout.WEST);

        JLabel ver = new JLabel("Xyrene NIDS v1.0   ");
        ver.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        ver.setForeground(FG_DIM);
        bar.add(ver, BorderLayout.EAST);
        return bar;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════════════════════
    private JButton makeBtn(String text, Color color) {
        JButton b = new JButton(text);
        b.setFont(new Font("Segoe UI", Font.BOLD, 12));
        b.setForeground(Color.WHITE);
        b.setBackground(color.darker());
        b.setFocusPainted(false);
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setPreferredSize(new Dimension(100, 30));
        return b;
    }

    private void loadInterfaces() {
        try {
            for (PcapNetworkInterface d : Pcaps.findAllDevs())
                ifCombo.addItem(d.getDescription() != null ? d.getDescription() : d.getName());
        } catch (PcapNativeException e) {
            ifCombo.addItem("ERROR: Npcap not installed");
            btnStart.setEnabled(false);
        }
    }

    private void refreshStats() {
        SwingUtilities.invokeLater(() -> {
            lblTotal.setText(String.valueOf(totalPkts));
            lblBenign.setText(String.valueOf(totalBenign));
            lblMalicious.setText(String.valueOf(totalMalicious));
            lblIps.setText(String.valueOf(ipStats.size()));
            double pct = totalPkts > 0 ? totalMalicious * 100.0 / totalPkts : 0;
            threatBar.setValue((int) pct);
            threatBar.setString(String.format("%.1f%%", pct));
            threatBar.setForeground(pct > 20 ? RED : pct > 5 ? YELLOW : GREEN);
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  CAPTURE
    // ═══════════════════════════════════════════════════════════════════════════
    private void startCapture() {
        int idx = ifCombo.getSelectedIndex();
        if (idx < 0) return;
        try {
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(idx);
            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 100);
            capturing = true;
            btnStart.setEnabled(false); btnStop.setEnabled(true); ifCombo.setEnabled(false);
            lblStatus.setText("\u25CF Capturing — " + nif.getName());
            lblStatus.setForeground(GREEN);

            captureThread = new Thread(() -> {
                try { handle.loop(-1, (PacketListener) this::onPacket); }
                catch (InterruptedException ignored) {}
                catch (Exception e) { SwingUtilities.invokeLater(() -> { lblStatus.setText("Error: " + e.getMessage()); lblStatus.setForeground(RED); }); }
            }, "Capture");
            captureThread.setDaemon(true);
            captureThread.start();

            if (batcherThread == null || !batcherThread.isAlive()) {
                batcherThread = new Thread(this::batchClassifierLoop, "Batcher");
                batcherThread.setDaemon(true);
                batcherThread.start();
            }
        } catch (Exception e) { lblStatus.setText("Failed: " + e.getMessage()); lblStatus.setForeground(RED); }
    }

    private void stopCapture() {
        capturing = false;
        if (handle != null) { try { handle.breakLoop(); } catch (Exception ignored) {} try { handle.close(); } catch (Exception ignored) {} }
        btnStart.setEnabled(true); btnStop.setEnabled(false); ifCombo.setEnabled(true);
        lblStatus.setText("\u25CF Stopped"); lblStatus.setForeground(FG_DIM);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  PACKET PROCESSING
    // ═══════════════════════════════════════════════════════════════════════════
    private void onPacket(org.pcap4j.packet.Packet raw) {
        if (!capturing) return;
        IpV4Packet ip = raw.get(IpV4Packet.class);
        if (ip == null) return;

        String srcIp = ip.getHeader().getSrcAddr().getHostAddress();
        int payloadSize = ip.getPayload() != null ? ip.getPayload().length() : 0;
        int headerLen = ip.getHeader().length();
        String protocol = "OTHER"; int srcPort = 0, dstPort = 0;
        boolean syn = false, ack = false, rst = false, fin = false, psh = false, urg = false;

        TcpPacket tcp = raw.get(TcpPacket.class);
        UdpPacket udp = raw.get(UdpPacket.class);
        if (tcp != null) { protocol = "TCP"; srcPort = tcp.getHeader().getSrcPort().valueAsInt(); dstPort = tcp.getHeader().getDstPort().valueAsInt();
            syn = tcp.getHeader().getSyn(); ack = tcp.getHeader().getAck(); rst = tcp.getHeader().getRst(); fin = tcp.getHeader().getFin(); psh = tcp.getHeader().getPsh(); urg = tcp.getHeader().getUrg();
        } else if (udp != null) { protocol = "UDP"; srcPort = udp.getHeader().getSrcPort().valueAsInt(); dstPort = udp.getHeader().getDstPort().valueAsInt(); }

        Packet pkt = new Packet();
        pkt.setSourceIp(srcIp); pkt.setDestinationIp(ip.getHeader().getDstAddr().getHostAddress());
        pkt.setSourcePort(srcPort); pkt.setDestinationPort(dstPort); pkt.setProtocol(protocol);
        pkt.setPayloadSize(payloadSize); pkt.setHeaderLength(headerLen); pkt.setTimestamp(Instant.now());
        pkt.setSynFlag(syn); pkt.setAckFlag(ack); pkt.setRstFlag(rst); pkt.setFinFlag(fin); pkt.setPshFlag(psh); pkt.setUrgFlag(urg);

        NidsFeatures features = extractFeatures(pkt);
        ipStats.computeIfAbsent(srcIp, k -> { int ri = nextRow.getAndIncrement(); int[] s = {0,0,0,ri}; SwingUtilities.invokeLater(() -> trafficModel.addRow(new Object[]{srcIp, 0, 0, 0, 0.0})); return s; });
        int[] stats = ipStats.get(srcIp);
        synchronized (stats) { stats[0]++; totalPkts++; }
        SwingUtilities.invokeLater(() -> { if (stats[3] < trafficModel.getRowCount()) trafficModel.setValueAt(stats[0], stats[3], 1); refreshStats(); });

        classifyQueue.offer(new ClassifyTask(srcIp, features));
    }

    private NidsFeatures extractFeatures(Packet p) {
        FlowKey fwd = new FlowKey(p.getSourceIp(), p.getDestinationIp(), p.getSourcePort(), p.getDestinationPort(), p.getProtocol());
        FlowKey rev = fwd.reversed();
        boolean isFw; FlowKey key;
        if (flowTable.containsKey(fwd)) { key = fwd; isFw = true; }
        else if (flowTable.containsKey(rev)) { key = rev; isFw = false; }
        else { key = fwd; isFw = true; flowTable.put(key, new FlowState()); flowDstPort.put(key, p.getDestinationPort()); }
        FlowState s = flowTable.get(key); s.addPacket(p, isFw);
        long pk = s.getTotFwPkts()+s.getTotBwPkts(), by = s.getTotLFwPkt()+s.getTotLBwPkt();
        double dur = 0; if (s.getFirstPacketTime()!=null && s.getLastPacketTime()!=null) dur = java.time.Duration.between(s.getFirstPacketTime(), s.getLastPacketTime()).toNanos()/1000.0;
        double sec = dur > 0 ? dur/1e6 : 1e-6;
        return new NidsFeatures(pk>0?(double)by/pk:0, pk/sec, s.getTotLFwPkt(), s.getTotLBwPkt(), dur, flowDstPort.getOrDefault(key,0), s.getRstCnt(), s.getSynCnt()/(s.getSynCnt()+s.getAckCnt()+1e-9));
    }

    private void batchClassifierLoop() {
        while (true) {
            try {
                Thread.sleep(250); // Send every 250ms
                if (classifyQueue.isEmpty()) continue;

                List<ClassifyTask> batch = new ArrayList<>();
                while (batch.size() < 100 && !classifyQueue.isEmpty()) {
                    ClassifyTask t = classifyQueue.poll();
                    if (t != null) batch.add(t);
                }
                if (batch.isEmpty()) continue;

                StringBuilder sb = new StringBuilder("{\"features\":[");
                for (int i = 0; i < batch.size(); i++) {
                    double[] a = batch.get(i).features.toArray();
                    sb.append(String.format("[%f,%f,%f,%f,%f,%f,%f,%f]", a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]));
                    if (i < batch.size() - 1) sb.append(",");
                }
                sb.append("]}");

                HttpURLConnection c = (HttpURLConnection) URI.create(API + "/batch").toURL().openConnection();
                c.setRequestMethod("POST"); c.setRequestProperty("Content-Type","application/json"); c.setDoOutput(true); c.setConnectTimeout(3000); c.setReadTimeout(5000);
                try (OutputStream os = c.getOutputStream()) { os.write(sb.toString().getBytes(StandardCharsets.UTF_8)); }

                String r = new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                String[] parts = r.split("\\},\\{"); // Dirty split array items

                for (int i = 0; i < batch.size(); i++) {
                    ClassifyTask task = batch.get(i);
                    boolean attack = false;
                    if (i < parts.length) {
                        attack = parts[i].contains("\"is_attack\": true") || parts[i].contains("\"is_attack\":true");
                    }
                    
                    int[] stats = ipStats.get(task.srcIp);
                    if (stats == null) continue;
                    
                    boolean finalAttack = attack;
                    synchronized (stats) { if (finalAttack) { stats[2]++; totalMalicious++; } else { stats[1]++; totalBenign++; } }

                    if (finalAttack) {
                        String time = LocalTime.now().format(TF);
                        SwingUtilities.invokeLater(() -> logModel.insertRow(0, new Object[]{time, task.srcIp, "ATTACK", "Malicious traffic detected from " + task.srcIp}));
                    }

                    SwingUtilities.invokeLater(() -> {
                        if (stats[3] < trafficModel.getRowCount()) {
                            trafficModel.setValueAt(stats[1], stats[3], 2);
                            trafficModel.setValueAt(stats[2], stats[3], 3);
                            double pct = (stats[1]+stats[2]) > 0 ? stats[2]*100.0/(stats[1]+stats[2]) : 0;
                            trafficModel.setValueAt(pct, stats[3], 4);
                        }
                    });
                }
                refreshStats();
            } catch (Exception e) {
                System.err.println("[NIDS Batcher] Error: " + e.getMessage());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  MAIN
    // ═══════════════════════════════════════════════════════════════════════════
    public static void main(String[] args) {
        FlatDarkLaf.setup();
        UIManager.put("TabbedPane.selectedBackground", new Color(40, 42, 54));
        UIManager.put("TabbedPane.underlineColor", new Color(0xFF, 0x66, 0x33));
        UIManager.put("TabbedPane.hoverColor", new Color(50, 52, 65));
        UIManager.put("Component.focusWidth", 0);
        SwingUtilities.invokeLater(() -> new PacketCaptureGui().setVisible(true));
    }
}
