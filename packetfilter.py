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
        # As of now just for show

def packetfilter_controller(ipc_variables):
    filter_packets(ipc_variables)
