# Add new rules to the firewall
# Check if a packet is malicious

from time import sleep
from concurrent.futures import ThreadPoolExecutor
from firewall import firewall_controller
from queue import Queue

pol_check_interval = 2

def filter_packets(ipc_variables):
    packet_check_flag = ipc_variables["packet_check_flag"]
    unfiltered_packets_queue = ipc_variables["unfiltered_packets_queue"]
    filtered_packets_queue = ipc_variables["filtered_packets_queue"]
    malicious_packets_queue = ipc_variables["malicious_packets_queue"]
    while(True):
        if(not packet_check_flag.value):
            # Dont filter the packets if filter flag is not set
            sleep(pol_check_interval)
            continue
        packet_count = unfiltered_packets_queue.qsize()
        temp_packets_queue = Queue()
        executor = ThreadPoolExecutor(max_workers=1000)
        threads = []
        for _ in range(0, packet_count):
            packet = unfiltered_packets_queue.get()
            temp_packets_queue.put(packet)
            thread = executor.submit(firewall_controller, packet)
            threads.append(thread)
        for thread in threads:
            result = thread.result()
            packet = temp_packets_queue.get()
            if(result): # Filtered Packet
                filtered_packets_queue.put(packet)
            else: # Malicious packet
                malicious_packets_queue.put(packet)

def packetfilter_controller(ipc_variables):
    # Create database objects here share with filter_packets
    filter_packets(ipc_variables)
