"""
Network-Layer Attacks - Shared Configuration v2.0
===================================================
DDoS parameters and timing calibrated against a realistic CPS environment.

Baseline target:
  200,000+ Zeek conn.log rows per 10-minute run
  -> Flood attacks: 1,000-10,000+ pkt/s
  -> Scanning/stealthy attacks: 2-100 pkt/s (realistic rates)

Class-balance strategy:
  Flood attacks naturally generate far more packets than stealthy ones.
  This is intentional and realistic - it is compensated for with
  class_weight during model training. Each attack class targets a
  minimum of 5,000 Zeek records.
"""

# ---------------------------------------------------------------------------
# Target IPs
# ---------------------------------------------------------------------------
PLC_IP      = "192.168.1.3"   # LattePanda - OpenPLC (Modbus :502)
HMI_IP      = "192.168.1.2"   # Node-RED HMI (:1880)
ROUTER_IP   = "192.168.1.1"   # Gateway

# ---------------------------------------------------------------------------
# Port definitions
# ---------------------------------------------------------------------------
MODBUS_PORT = 502
HMI_PORT    = 1880
SSH_PORT    = 22

import os

# ---------------------------------------------------------------------------
# Zeek log directory
# ---------------------------------------------------------------------------
ZEEK_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zeek_logs")
PCAP_DIR     = "/tmp/pcaps"

# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------
NET_LOOP_DELAY        = 0.1    # 100ms - normal/scanning modes
NET_ATTACK_LOOP_DELAY = 0.001  # 1ms   - flood modes (packet generation only)

# Production-mode durations (seconds):
# Flood: 600s x 2000 pkt/s = 1,200,000 packets -> hundreds to thousands of Zeek conn records
# Scan:  600s x 5 pkt/s = 3,000 packets -> ~1,500 Zeek conn records
DEFAULT_NET_DURATION  = 600    # 10 minutes (production default)

# ---------------------------------------------------------------------------
# Attack durations (production mode)
# ---------------------------------------------------------------------------
# Overridden by masterrunner.py via --attack-time; the values below are only
# used when network_attack_runner.py is invoked standalone.
NET_DURATIONS = {
    # Flood attacks -> high pkt/s -> enough data in a short time
    "icmp_flood":      600,    # ~2000 pkt/s x 600s = 1.2M packets
    "udp_flood":       600,    # ~10000 pkt/s x 600s = 6M packets
    "tcp_syn_flood":   600,    # ~2000 pkt/s x 600s = 1.2M packets
    "tcp_ack_flood":   600,    # ~1500 pkt/s x 600s = 900K packets
    "http_flood":      600,    # ~500 req/s x 600s = 300K requests
    # Scanning/stealthy attacks -> low pkt/s -> longer duration
    "port_scan":       600,    # ~5 pkt/s x 600s = 3K packets (full port list repeated)
    "os_scan":         300,    # ~68 pkt/s x 300s = 20K packets
    "vuln_scan":       600,    # ~68 pkt/s x 600s = 41K packets
    "nodered_injection": 600,  # ~10 req/s x 600s = 6K requests
    "insider_threat":  600,    # ~2.5 pkt/s x 600s = 1.5K packets
    "apt_exfil":       600,    # ~4 pkt/s x 600s = 2.4K packets
    "modbus_abuse":    600,    # ~2 pkt/s x 600s = 1.2K requests
}

# ---------------------------------------------------------------------------
# Flood-attack set
# ---------------------------------------------------------------------------
# These attacks run with minimal delay (thread-based packet generation).
FLOOD_ATTACKS = {
    "icmp_flood", "udp_flood", "tcp_syn_flood",
    "tcp_ack_flood", "http_flood", "os_scan",
}


def get_net_loop_delay(attack_name: str) -> float:
    """Returns the appropriate loop delay for the given attack type."""
    return NET_ATTACK_LOOP_DELAY if attack_name in FLOOD_ATTACKS else NET_LOOP_DELAY


# ---------------------------------------------------------------------------
# Label definitions (separate from physical attacks, starting at 100)
# ---------------------------------------------------------------------------
LABEL_NET_NORMAL             = 100
LABEL_ICMP_FLOOD             = 101
LABEL_UDP_FLOOD              = 102
LABEL_TCP_SYN_FLOOD          = 103
LABEL_TCP_ACK_FLOOD          = 104
LABEL_HTTP_FLOOD             = 105
LABEL_PORT_SCAN              = 106
LABEL_OS_SCAN                = 107
LABEL_VULN_SCAN              = 108
LABEL_NODERED_API_INJECTION  = 109
LABEL_INSIDER_THREAT         = 110
LABEL_APT_EXFIL              = 111
LABEL_MODBUS_ABUSE           = 112

NETWORK_ATTACK_NAMES = {
    100: "Normal_Traffic",
    101: "ICMP_Flood",
    102: "UDP_Flood",
    103: "TCP_SYN_Flood",
    104: "TCP_ACK_Flood",
    105: "HTTP_Flood",
    106: "Port_Scan",
    107: "OS_Scan",
    108: "Vulnerability_Scan",
    109: "NodeRED_API_Injection",
    110: "Insider_Threat",
    111: "APT_Exfiltration",
    112: "Modbus_Abuse",
}

# ---------------------------------------------------------------------------
# Expected data volume (production mode: 600s/attack)
# ---------------------------------------------------------------------------
# Estimated Zeek conn.log row counts.
EXPECTED_ZEEK_ROWS = {
    "icmp_flood":     72000,    # ~2000 pkt/s x 600s / 10-50 (Zeek conn aggregation)
    "udp_flood":      360000,   # ~10000 pkt/s x 600s / ~10-17
    "tcp_syn_flood":  120000,   # ~2000 pkt/s x 600s / ~10
    "tcp_ack_flood":  90000,    # ~1500 pkt/s x 600s / ~10
    "http_flood":     300000,   # ~500 req/s x 600s (each request = 1 conn record)
    "port_scan":      3000,     # ~5 pkt/s x 600s = 1 record per port
    "os_scan":        20000,    # ~68 pkt/s x 300s
    "vuln_scan":      41000,    # ~68 pkt/s x 600s
    "nodered_injection": 6000,  # ~10 req/s x 600s
    "insider_threat": 1500,     # ~2.5 pkt/s x 600s
    "apt_exfil":      2400,     # ~4 pkt/s x 600s
    "modbus_abuse":   1200,     # ~2 pkt/s x 600s
}
