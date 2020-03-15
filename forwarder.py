# Forwards the packet accordingly

import threading
from scapy.all import *

honeypot_ip = "127.0.0.1"
resource_ip = "127.0.0.1"

def create_forward_packet(pyshark_object, destination):
    packet = IP()/UDP()
    packet[IP].dest = destination
    return packet

def send_packet(packet):
    send(packet)

def send_to_honeypot(ipc_variables):
    filtered_packets_queue = ipc_variables["filtered_packets_queue"]
    while(True):
        count = filtered_packets_queue.qsize()
        while(count):
            filtered_packet = filtered_packets_queue.get() 
            try:
                scapy_object = create_forward_packet(filtered_packet, honeypot_ip) # Form packet code
                send_packet(scapy_object) # Send to IP code
            except Exception as e:
                print(e)
            count -= 1

def send_to_backend(ipc_variables):
    malicious_packets_queue = ipc_variables["malicious_packets_queue"]
    while(True):
        count = malicious_packets_queue.qsize()
        while(count):
            malicious_packet = malicious_packets_queue.get() 
            try:    
                scapy_object = create_forward_packet(malicious_packet, resource_ip) # Form packet code
                send_packet(scapy_object) # Send to IP code
            except Exception as e:
                print(e)
            count -= 1

def forwarder_controller(ipc_variables):
    send_to_honeypot_thread = threading.Thread(target=send_to_honeypot, args=(ipc_variables,))
    send_to_backend_thread = threading.Thread(target=send_to_backend, args=(ipc_variables,))
    send_to_honeypot_thread.start()
    send_to_backend_thread.start()