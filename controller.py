# Controller to start all other processes/jobs
# Using the python multiprocessing package

from time import sleep
import multiprocessing
import daemon
import packetfilter
import sniffer
import traffictrigger

def controller():
    
    ipc_variables = {} # All queues are stored here
    
    packet_queue = multiprocessing.Queue() # All packets sniffed are stored here
    filtered_packets_queue = multiprocessing.Queue() # Queue that stores all filtered packets
    unfiltered_packets_queue = multiprocessing.Queue() # Queue that stores all unfiltered packets
    malicious_packets_queue = multiprocessing.Queue() # Queue that stores all malicious packets
    packet_check_flag = multiprocessing.Value('b', False) # Initially setting to 0 to not check for value
    
    ipc_variables["packet_queue"] = packet_queue
    ipc_variables["filtered_packets_queue"] = filtered_packets_queue
    ipc_variables["unfiltered_packets_queue"] = unfiltered_packets_queue
    ipc_variables["malicious_packets_queue"] = malicious_packets_queue
    ipc_variables["packet_check_flag"] = packet_check_flag  

    packetfilter_process = multiprocessing.Process(target=packetfilter.packetfilter_controller, args=(ipc_variables,))
    sniffer_process = multiprocessing.Process(target=sniffer.sniffer_controller, args=(ipc_variables,))
    traffictrigger_process = multiprocessing.Process(target=traffictrigger.traffictrigger_controller, args=(ipc_variables,))
    
    packetfilter_process.start()
    sniffer_process.start()
    traffictrigger_process.start()

if __name__ == "__main__":
    controllerprocess = multiprocessing.Process(target=controller)
    controllerprocess.start()