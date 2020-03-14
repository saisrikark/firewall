# Will be the first entry point for a packet
# From here check for already present firewall rules
# If the layer 1 /time based trigger is hit forward to 
# the layer 2 trigger

import pyshark
import threading 
import time

max_queue_size = 500
capture = pyshark.LiveCapture(interface = 'wlan0')
j = 0

def write_into_file(ipc_variables, capture_list, start_index, end_index):
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
        except:
            fp = open("packets.log","a")
            fp.write("Failed To Log The Packet\n")
            fp.close()
    if(packet_queue.qsize() > max_queue_size):
        print("Queue size before removing elements", packet_queue.qsize())
        while(not packet_queue.empty()):
            packet_queue.get()
        print("Queue size after removing elements", packet_queue.qsize())

def read_packets(ipc_variables):
    packet_queue = ipc_variables["packet_queue"]
    unfiltered_packets_queue = ipc_variables["unfiltered_packets_queue"]
    while(len(capture) == 0):
        time.sleep(5)
    older_count = 0
    while(True):
        new_count = len(capture)
        if(new_count != older_count):
            #print(str(older_count) + " " + str(new_count))
            for index in range(older_count, new_count):
                packet_queue.put(capture[index])
                unfiltered_packets_queue.put(capture[index])
            write_into_file(ipc_variables, capture, older_count, new_count)
            older_count = new_count
            time.sleep(10)

def sniffer_controller(ipc_variables):
    t1 = threading.Thread(target=read_packets, args=(ipc_variables,))
    t1.start()
    capture.sniff()
