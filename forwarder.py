# Forwards the packet accordingly

import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
#from scapy.layers import *

honeypot_ip = "192.168.0.110"
resource_ip = "192.168.0.110" #"127.0.0.1"
s = conf.L3socket(iface='wlan0')
fd = open("packets.log", "a")

#########################################################################################
def create_forward_packet(pyshark_object, destination):
    py_eth_src = pyshark_object['eth'].src
    py_eth_dst = pyshark_object['eth'].dst
    py_dport = int(pyshark_object[pyshark_object.transport_layer.lower()].dstport)
    py_sport = int(pyshark_object[pyshark_object.transport_layer.lower()].srcport)
    py_ip_src = pyshark_object['ip'].src
    py_ip_dst = destination
    print(py_dport, py_sport, py_eth_src, py_eth_dst)
    packet = IP(src=py_ip_src,dst=py_ip_dst)/UDP(dport=py_dport, sport=py_sport)
    return packet

def send_packet(packet):
    s.send(packet)

def log_packet(packet, dest_name):
    packet_log = ""
    try:
        packet_log = str(packet.sniff_timestamp) + " " + dest_name + " "
        try:
            packet_log += packet['eth'].src + " " + packet['eth'].dst + " "
        except:
            packet_log += "NA" + " " + "NA" + " "
        try:
            packet_log += packet[packet.transport_layer.lower()].srcport + " " + packet[packet.transport_layer.lower()].dstport + " "
        except:
            packet_log += "NA" + " " + "NA" + " "
        if("ip" in packet):
            packet_log += packet['ip'].src + " " + packet['ip'].dst + "\n"
        else:
            packet_log += packet['ipv6'].src + " " + packet['ipv6'].dst + "\n"
    except:
        pass
    fd.write(packet_log)
    
def perform_packet_operations(packet, ip, dest_name):
    scapy_object = create_forward_packet(packet, ip) # Form packet code
    send_packet(scapy_object) # Send to IP code
    log_packet(packet, dest_name)

def send_to_honeypot(ipc_variables):
    malicious_packets_queue = ipc_variables["malicious_packets_queue"]
    executor = ThreadPoolExecutor(max_workers=10000)
    while(True):
        count = malicious_packets_queue.qsize()
        while(count):
            filtered_packet = malicious_packets_queue.get() 
            try:
                print("#")
                executor.submit(perform_packet_operations, filtered_packet, honeypot_ip, "honeypot")
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
                executor.submit(perform_packet_operations, malicious_packet, resource_ip, "resource")
            except Exception as e:
                print(e)
            count -= 1

def forwarder_controller(ipc_variables):
    send_to_honeypot_thread = threading.Thread(target=send_to_honeypot, args=(ipc_variables,))
    send_to_backend_thread = threading.Thread(target=send_to_backend, args=(ipc_variables,))
    send_to_honeypot_thread.start()
    send_to_backend_thread.start()