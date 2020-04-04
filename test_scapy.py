from scapy.all import *
packet = Ether()/IP()/UDP()
packet[IP].dest = "192.168.0.110"
packet[UDP].dport = 20
send(packet)
