from database import import_packets

def is_already_malicious(packet):
    # Go through all rules of the firewall and check if already malicious
    # Check against already malicious packets table
    return True

def is_malicious(updated_packet_data):
    # Checks packet not already deemed malicious for maliciousness
    # Rules might differ from the is_already_malicious function
    return True

def firewall_controller(packet):
    if(is_already_malicious(packet)): 
        return False
    else:
        #update_table_with_packet("ambiguous_packets_table", packet)
        updated_packet_data = ()#fetch_row_from_table("ambigious_packet_table", packet) 
        if(is_malicious(updated_packet_data)):
            #update_table_with_packet("malicious_packets_table", packet)
            return False
        else: 
            return True

