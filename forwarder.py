# Forwards the packet accordingly

import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *

honeypot_ip = "127.0.0.1"
resource_ip = "127.0.0.1"
s = conf.L3socket(iface='wlan0')

def create_forward_packet(pyshark_object, destination):
    packet = IP()/UDP()
    packet[IP].dest = destination
    packet[IP].src = "1.1.1.1"
    return packet

def send_packet(packet):
    s.send(packet)

def perform_packet_operations(packet, ip):
    scapy_object = create_forward_packet(packet, ip) # Form packet code
    send_packet(scapy_object) # Send to IP code

def send_to_honeypot(ipc_variables):
    malicious_packets_queue = ipc_variables["malicious_packets_queue"]
    executor = ThreadPoolExecutor(max_workers=10000)
    while(True):
        count = malicious_packets_queue.qsize()
        while(count):
            filtered_packet = malicious_packets_queue.get() 
            try:
                print("#")
                executor.submit(perform_packet_operations, filtered_packet, honeypot_ip)
            except Exception as e:
                print(e)
            count -= 1

def send_to_backend(ipc_variables):
    filtered_packets_queue = ipc_variables["filtered_packets_queue"]
    executor = ThreadPoolExecutor(max_workers=10000)
    while(True):
        count = filtered_packets_queue.qsize()
        while(count):
            malicious_packet = filtered_packets_queue.get()
            try:   
                print('*')
                perform_packet_operations(malicious_packet, resource_ip)
                executor.submit(perform_packet_operations, malicious_packet, resource_ip)
            except Exception as e:
                print(e)
            count -= 1

def forwarder_controller(ipc_variables):
    send_to_honeypot_thread = threading.Thread(target=send_to_honeypot, args=(ipc_variables,))
    send_to_backend_thread = threading.Thread(target=send_to_backend, args=(ipc_variables,))
    send_to_honeypot_thread.start()
    send_to_backend_thread.start()
