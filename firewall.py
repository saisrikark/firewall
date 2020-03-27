from database import import_packets

def is_already_malicious(packet):
    # Go through all rules of the firewall and check if already malicious
    # Check against already malicious packets table
    return True

def is_malicious(packet):
    # Checks packet not already deemed malicious for maliciousness
    # Rules might differ from the is_already_malicious function
    return True

def firewall_controller(packet):
    if(is_already_malicious(packet)): # Checking packets with rules against already deemed malicious packets
        return False
    else:
        # Update packet into table with all packets
        # Fetch the row of the same packet
        packet_data = () # Row that is fetched
        if(is_malicious(packet_data)):
            # Add packet into the malicious packets table
            return False
        else: 
            return True

