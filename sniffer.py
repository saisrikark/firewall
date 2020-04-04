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
inserting_into_queue_flag = False
clearing_list_flag = False
clear_list_interval = 10
clear_list_packet_threshold = 100
packet_beginning_index = 0
packet_ending_index = 0
curr_machine_ip = "192.168.0.100"

def read_packets(ipc_variables):
    global packet_beginning_index
    global packet_ending_index
    unfiltered_packets_queue = ipc_variables["unfiltered_packets_queue"]
    while(len(capture) == 0):
        time.sleep(1)
    while(True):
        packet_ending_index = len(capture)
        if(packet_ending_index - packet_beginning_index):
            while(clearing_list_flag):
                pass
            inserting_into_queue_flag = True
            for index in range(packet_beginning_index, packet_ending_index):
                try:
                    if(capture[index]['ip'].src == curr_machine_ip):
                        print(capture[index]['ip'].src, "passing")
                        continue
                    unfiltered_packets_queue.put(capture[index])
                except Exception as e:
                    pass
            packet_beginning_index = packet_ending_index
            inserting_into_queue_flag = False

def clear_list():
    global clearing_list_flag
    global packet_beginning_index
    global packet_ending_index
    print("Clear list started")
    while(True):
        time.sleep(clear_list_interval)
        if(len(capture) > clear_list_packet_threshold):
            while(inserting_into_queue_flag):
                pass
            clearing_list_flag = True
            capture.clear()
            packet_beginning_index = 0
            packet_ending_index = 0
            clearing_list_flag = False
            print("Clearing list", len(capture))

def sniffer_controller(ipc_variables):
    global ipc_variables_glb
    ipc_variables_glb = ipc_variables
    read_packets_thread = threading.Thread(target=read_packets, args=(ipc_variables,))
    clear_list_thread = threading.Thread(target=clear_list)
    read_packets_thread.start()
    clear_list_thread.start()
    capture.sniff()
