def is_already_malicious(packet, db):
    # Go through all rules of the firewall and check if already malicious
    # Check against already malicious packets table
    return True

def is_malicious(updated_packet_data, db):
    # Checks packet not already deemed malicious for maliciousness
    # Rules might differ from the is_already_malicious function
    return True

def firewall_controller(packet, db):
    if(is_already_malicious(packet, db)):
        return False
    else:
        db.update_table_with_packet("ambiguous_packets_table", packet)
        updated_packet_data = db.fetch_row_from_table("ambigious_packet_table", packet)
        if(is_malicious(updated_packet_data, db)):
            db.update_table_with_packet("malicious_packets_table", packet)
            return False
        else: 
            return True

