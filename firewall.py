import time
from database import SqlDatabase

def extract_parameter(packet):
    sniff_timestamp = packet.sniff_timestamp
    try:
        eth_src = packet['eth'].src
        eth_dst = packet['eth'].dst
        src_port = packet[packet.transport_layer.lower()].srcport
        dst_port = packet[packet.transport_layer.lower()].dstport
        src_ip = packet['ip'].src
        dst_ip = packet['ip'].dst
        parameters = (sniff_timestamp,src_ip,dst_ip,src_port,dst_port,eth_src,eth_dst)
    except:
        parameters = ()
    return parameters

def is_already_malicious(packet, db):
    # Check against already malicious packets table
    if(not packet):
        return False
    src_ip = packet[1]
    malicious_packets_for_ip = db.get_packets_with_ip("malicious_packets_table", src_ip)
    if(not malicious_packets_for_ip):
        return False
    return True

def check_interval(packet, sql_object):
    src_ip = ""
    if 'ip' in packet:
        src_ip = packet['ip'].src
    elif 'ipv6' in packet:
        src_ip = packet['ipv6'].src
    else:
        return True
    packets_list = sql_object.get_packets_with_ip("ambiguous_packets_table",src_ip)
    current_timestamp = int(time.time())
    time_interval = 15
    no_of_packets = 100
    packet_count = 0
    for i in packets_list:
        if (current_timestamp - float(i[0])) < time_interval:
            packet_count += 1
        if packet_count >= no_of_packets:
            return True
    return False

def check_high_port(capture):
    try:
        if int(capture[capture.transport_layer.lower()].srcport) > 60000 or int(capture[capture.transport_layer.lower()].dstport) > 60000:
            return True
        return False
    except:
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
    ip_list = ['10.0.0.8','172.16.0.0','192.168.0.0','0.0.0.0','127.0.0.0','169.254.0.0','192.0.2.0','240.0.0.0','248.0.0.0','255.255.255.255']
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
    print("Checking if malicious")
    # Checks packet not already deemed malicious for maliciousness
    # Rules might differ from the is_already_malicious function
    malicious_count = 0
    interval_status = check_interval(packet, db)
    if(interval_status):
        print("Interval surge")
        malicious_count += 1
    high_port_status = check_high_port(packet)
    if(high_port_status):
        print("High port")
        malicious_count += 1
    proto_number = 17
    proto_status = unexpected_proto(packet,proto_number)
    if(proto_status):
        print("Proto")
        malicious_count += 1
    unexpected_ip_status = unexpected_ip(packet)
    if(unexpected_ip_status):
        print("Unexpected ip")
        malicious_count += 1
    if malicious_count <= 1:
        return False
    return True

def firewall_controller(packet):
    db = SqlDatabase("root", "", "localhost")
    db.my_database = "mysql"
    extracted_packet = extract_parameter(packet)
    if (is_already_malicious(extracted_packet, db)):
        print("Already Deemed malicious", extracted_packet)
        return False
    else:
        if (not extracted_packet):
            return True
        db.insert_packets("ambiguous_packets_table", extracted_packet)
        if (is_malicious(packet, db)):
            db.insert_packets("malicious_packets_table", extracted_packet)
            print("Deemed Malicious", extracted_packet)
            return False
        else:
            print("Not malicious", extracted_packet)
            return True
