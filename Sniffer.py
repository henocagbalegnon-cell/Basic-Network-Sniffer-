from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


# Fonction appelée pour chaque paquet capturé
def process_packet(packet):

    # On ne traite que les paquets IPv4
    if IP not in packet:
        return

    # Récupération des adresses IP
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Identification du protocole
    if TCP in packet:

        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:

        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:

        protocol = "ICMP"
        src_port = "-"
        dst_port = "-"

    else:

        protocol = "Other"
        src_port = "-"
        dst_port = "-"

    # Récupération du payload
    if Raw in packet:
        payload = packet[Raw].load
    else:
        payload = "Aucun payload"

    # Affichage des informations
    print("========================================")
    print(f"Source      : {src_ip}:{src_port}")
    print(f"Destination : {dst_ip}:{dst_port}")
    print(f"Protocol    : {protocol}")
    print(f"Size        : {len(packet)} bytes")
    print(f"Payload     : {payload}")
    print("========================================")


# Message de démarrage
print("========================================")
print("       BASIC NETWORK SNIFFER")
print("========================================")
print("Capture en cours...")
print("Filtre : TCP")
print("Appuyez sur CTRL+C pour arrêter.")
print()


# Capture des paquets TCP
sniff(
    filter="tcp",
    prn=process_packet,
    count=10
)