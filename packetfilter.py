# Add new rules to the firewall
# Check if a packet is malicious

from time import sleep

pol_check_interval = 2

def filter_packets(ipc_variables):
    packet_check_flag = ipc_variables["packet_check_flag"]
    while(True):
        if(not packet_check_flag.value):
            # Dont filter the packets if filter flag is not set
            sleep(pol_check_interval)
            continue
        # Filtering has to be done here
        # Start multiple threads for each packet check
        # If deemed as malicious, update in malicious_packets_queue, continue
        # Else update packet in packet log database
        # If a trigger is hit when updating the database
            # update in malicious_packets_queue
            # update in firewall database
        # Else
            # update in filtered_packets_queue

def packetfilter_controller(ipc_variables):
    # Create database objects here share with filter_packets
    filter_packets(ipc_variables)
