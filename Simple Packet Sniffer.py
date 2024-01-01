from scapy.layers.inet import IP, TCP, UDP, Ether, ICMP
from scapy.all import sniff
import pyfiglet

# variable to track if the banner has been displayed or not yet
banner_displayed = False
def Banner () :
    ascii_banner = pyfiglet.figlet_format("AlphaScan")
    print('-'*70)
    print(ascii_banner)
    print('-'*70)

# Extract from each packet the source and destination ip and store it in ip_src and ip_dst
def process_ip(packet):
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    print(f"[<!?>] IP Packet from {ip_src} to {ip_dst}")


# Extract from each packet the source and destination Mac AAddress and store it in mac_src and mac_dst
def process_ethernet(packet):
    mac_src = packet[Ether].src
    mac_dst = packet[Ether].dst
    print(f"[<$>] Source MAC: {mac_src}, Destination MAC: {mac_dst}")


# Extract from each TCP packet the source and destination port and store it in src_port and dst_port
def process_tcp(packet):
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    print(f"[TCP] Source Port: {src_port}, Destination Port: {dst_port}")


# Extract from each UDP packet the source and destination port and store it in src_port and dst_port
def process_udp(packet):
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport
    print(f"[UDP] Source Port: {src_port}, Destination Port: {dst_port}")


# Extract from each ICPM request the type and code and store it in icmp_type and icmp_code
def process_icmp(packet):
    icmp_type = packet[ICMP].type
    icmp_code = packet[ICMP].code
    print(f"[<^^>] ICMP Packet - Type: {icmp_type}, Code: {icmp_code}")

# Main Function
def packet_sniffer(packet):

    global banner_displayed

    if not banner_displayed:
        Banner()
        banner_displayed = True

    if IP in packet:
        process_ip(packet)

    if Ether in packet:
        process_ethernet(packet)

    if TCP in packet:
        process_tcp(packet)

    if UDP in packet:
        process_udp(packet)

    if ICMP in packet:
        process_icmp(packet)

# Sniff: function in Scapy used for packet sniffing
# The prn parameter: specifies a callback function that will be called for each packet sniffed.
# store=False: indicating that sniffed packets will not be stored in memory, it's set to False to conserve memory.
sniff(prn=packet_sniffer, store=False, filter="tcp or udp or icmp")
