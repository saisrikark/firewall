# Add new rules for a malicious packet

def update_packet_to_db(packet):
    # Adds packets to the packets db if not present
    # Else updates the existing packet
    # Return a trigger true or false value if necessary
    pass

def add_packet_to_firewall_rule(rule):
    # Will add the firewall rule into firewall db
    # Some logic is required as to how to add and what attributes to add
    pass

def firewall_rules_checker(packet):
    # Go through all rules of the firewall and check
    # We must have custom rules not just check for IP
    # Whether packet is already deemed malicious
    # Return appropriate True/False value
    pass
