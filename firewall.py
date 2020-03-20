def add_packet_to_firewall_rule(rule):
    # Will add the firewall rule into firewall db
    # Logic is required as to how to add and what attributes to add
    pass

def fetch_packet_from_db(packet):
    # Retrieves packet from DB - packet log table
    # Some maliciousness checks are performed on this packet
    pass

def update_packet_to_db(packet):
    # Adds packets to the packet log table in DB if not present
    # Else updates the existing packet
    pass

def firewall_rules_checker(packet):
    # Go through all rules of the firewall and check
    # We must have custom rules - not just check for IP
    # i.e Whether packet is already deemed malicious
    # Return appropriate True/False value
    pass

def firewall_controller(packet):
    # print("In firewall controller", packet)
    return False # Packet is malicious
    
    # Steps to be followed as of now
    # Check packet against all firewall rules / firewall_rules_checker
    #   If there's a hit return False
    # Update Packet to the table with all packets
    # Fetch packet data from the table again
    # Check if any hits against another set of firewall rules
    # If there's a hit, update in the firewall table and return False
    # Else return True
