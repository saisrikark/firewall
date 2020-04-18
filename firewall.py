import time
def is_already_malicious(packet, db):
    # Go through all rules of the firewall and check if already malicious
    # Check against already malicious packets table
    return False

def check_interval(packet, sql_object):

    if 'ip' in packet:
        src_ip = packet['ip'].src
    elif 'ipv6' in packet:
        src_ip = packet['ipv6'].src
    else:
        return True

    packets_list = sql_object.get_packets_with_ip("packets",src_ip)
    current_timestamp = int(time.time())

    time_interval = 15
    no_of_packets = 20
    packet_count = 0

    for i in packets_list:
        if (current_timestamp - int(i[0])) < time_interval:
            packet_count += 1

        if packet_count >= no_of_packets:
            return True

    return False

def check_high_port(capture):
        try:
            if int(capture[capture.transport_layer.lower()].srcport) > 60000 or int(capture[capture.transport_layer.lower()].dstport) > 60000:
                return True
            return False
        except Exception as excp:
            return True

def unexpected_proto(capture,protocol_number):
    if 'ip' in capture:
        if int(capture['ip'].proto) == protocol_number:
            return True
        return False

    if 'ipv6' in capture:
        if int(capture['ipv6'].proto) == protocol_number:
            return True
        return False

    return True

def unexpected_ip(packet):
    ip_list = ['10.0.0.8','172.16.0.0','192.168.0.0','0.0.0.0','127.0.0.0','169.254.0.0','192.0.2.0','240.0.0.0','248.0.0.0','255.255.255.255'] #add ips

    if 'ip' in packet:
        src_ip = packet['ip'].src
    elif 'ipv6' in packet:
        src_ip = packet['ipv6'].src
    else:
        return True

    if src_ip in ip_list:
        return True
    return False

def is_malicious(packet, db):
    # Checks packet not already deemed malicious for maliciousness
    # Rules might differ from the is_already_malicious function
    malicious_count = 0

    interval_status = check_interval(packet, db)
    if(interval_status):
        malicious_count += 1

    high_port_status = check_high_port(packet)
    if(high_port_status):
        malicious_count += 1

    proto_number = 17
    proto_status = unexpected_proto(packet,proto_number)
    if(proto_status):
        malicious_count += 1

    unexpected_ip_status = unexpected_ip(packet)
    if(unexpected_ip_status):
        malicious_count += 1

    if malicious_count >= 3:
        return False

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
