# The traffic based trigger - 
# based on packet transmission statistics

from time import sleep

# total_packet_count = 0
delta_packet_count = 0 # Number of packets between delta time
delta_time = 5 # In between time to check for count of packets

unfiltered_packets_queue = None
filtered_packets_queue = None

def trigger_rule(after_packet_count, before_packet_count):
    # Rule - packets/sec > threshold
    return ((after_packet_count - before_packet_count)/delta_time) > 100

def check_delta_surge(ipc_variables):
    # Check if there is an unwanted surge in packets between delta time
    before_packet_count = unfiltered_packets_queue.qsize()
    sleep(delta_time)
    after_packet_count = unfiltered_packets_queue.qsize()
    print("\nDiff", after_packet_count-before_packet_count)
    if(trigger_rule(after_packet_count, before_packet_count)):
        print("\nSurge in traffic detected, initializing packet check")
        packet_check_flag = ipc_variables["packet_check_flag"]
        packet_check_flag.value = True # Set the flag to check the packets
    else:
        # Update the filtered packet list
        packet_check_flag = ipc_variables["packet_check_flag"]
        packet_check_flag.value = False # Set the flag to not check the packets
        count = unfiltered_packets_queue.qsize()
        while(count):
            count -= 1
            filtered_packets_queue.put(unfiltered_packets_queue.get())
        #print("Unfiltered queue size after filtering", unfiltered_packets_queue.qsize())
        #print("Filtered queue size", filtered_packets_queue.qsize(), "change", count)

def traffictrigger_controller(ipc_variables):
    global unfiltered_packets_queue
    global filtered_packets_queue
    unfiltered_packets_queue = ipc_variables["unfiltered_packets_queue"]
    filtered_packets_queue = ipc_variables["filtered_packets_queue"]
    while(True):
        check_delta_surge(ipc_variables)
