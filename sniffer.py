# Will be the first entry point for a packet
# From here check for already present firewall rules
# If the layer 1 /time based trigger is hit forward to 
# the layer 2 trigger

import pyshark
import threading 
import time

max_queue_size = 500
capture = pyshark.LiveCapture(interface = 'wlan0')
logging_packets_counter = 0
j = 0

def packet_logger(ipc_variables, capture_list):
    print("Logging packets to packets.log")
    global logging_packets_counter
    start_index = logging_packets_counter
    end_index = len(capture_list)
    packet_queue = ipc_variables["packet_queue"]
    for i in range(start_index,end_index):
        try:
            global j
            packet_log = str(j) + " " + str(capture_list[i].sniff_timestamp) + " "
            j = j + 1
            packet_log = packet_log + capture_list[i]['eth'].src + " " + capture_list[i]['eth'].dst + " " 
            packet_log = packet_log + capture_list[i][capture_list[i].transport_layer.lower()].srcport + " " 
            packet_log = packet_log + capture_list[i][capture_list[i].transport_layer.lower()].dstport + " "
            if("ip" in capture_list[i]):
                packet_log = packet_log + capture_list[i]['ip'].src + " " + capture_list[i]['ip'].dst + "\n"
            else:
                packet_log = packet_log + capture_list[i]['ipv6'].src + " " + capture_list[i]['ipv6'].dst + "\n"
            fp = open("packets.log", "a")
            fp.write(packet_log)
            fp.close()
        except Exception as e:
            fp = open("packets.log","a")
            fp.write("Failed To Log The Packet " + str(e) + "\n")
            fp.close()
    logging_packets_counter = end_index
    if(packet_queue.qsize() > max_queue_size):
        print("Queue size before removing elements", packet_queue.qsize())
        count = packet_queue.qsize()
        while(count):
            count -= 1
            packet_queue.get()
        print("Queue size after removing elements", packet_queue.qsize())

def packet_logger_controller(ipc_variables, capture_list):
    while(True):
        time.sleep(5)
        packet_logger(ipc_variables, capture_list)

def read_packets(ipc_variables):
    older_count = new_count = 0
    packet_queue = ipc_variables["packet_queue"]
    unfiltered_packets_queue = ipc_variables["unfiltered_packets_queue"]
    while(len(capture) == 0):
        time.sleep(5)
    while(True):
        new_count = len(capture)
        if(new_count != older_count):
            for index in range(older_count, new_count):
                packet_queue.put(capture[index])
                unfiltered_packets_queue.put(capture[index])
            older_count = new_count

def sniffer_controller(ipc_variables):
    global ipc_variables_glb
    ipc_variables_glb = ipc_variables
    read_packets_thread = threading.Thread(target=read_packets, args=(ipc_variables,))
    packet_logger_thread = threading.Thread(target=packet_logger_controller, args=(ipc_variables, capture))
    read_packets_thread.start()
    packet_logger_thread.start()
    capture.sniff()
