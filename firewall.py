from netfilterqueue import NetfilterQueue
from database import import_packets
import subprocess
import os

nfqueue = NetfilterQueue()
nfqueue.bind(1,update_packet_to_db)

cmd = 'iptables'

'''
#mitigating SYN flood
iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack 
iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460 
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
'''

def add_packet_to_malicious_packet_table(packet):
    # Will add the malicious ip into malicious packet table
    insert_packets("malicious_packets",packet)

def update_packet_to_db(packet):
    packet = tuple(packet[1],packet[6],packet[7],packet[4], packet[5], packet[2], packet[3])
    add_packet_to_malicious_packet_table(packet)
    insert_packets("packets",packet)

def firewall_rules_checker(packet):
    # Go through all rules of the firewall and check
    # We must have custom rules - not just check for IP
    # i.e Whether packet is already deemed malicious
    # Return appropriate True/False value
    pkt = packet

    #block a specific IP Address
    subprocess.call(cmd, pkt, '-s ', '-j NFQUEUE', '--queue-num 1')

    #block network flood
    block_ip_network = subprocess.call(cmd, pkt, '-p tcp', '--dport 80', '-m limit', '--limit 50/minute', '--limit-burst 100', '-j ACCEPT')

    #block access to specific MAC addresses
    block_mac_address = subprocess.call(cmd, pkt, '-m mac', '--mac 00:00:00:00:00:00', '-j NFQUEUE', '--queue-num 1')

    #limit concurrent connections for per IP
    limit_per_IP = subprocess.call(cmd, pkt, '-p tcp', '--syn', '--dport 22', '-m connlimit', '--conlimit-above 3', '-j NFQUEUE', '--queue-num 1')

    #block invalid packets
    block_invalid_packets = subprocess.call(cmd, pkt, '-A PREROUTING', '-m conntrack', '--ctstate INVALID', '-j NFQUEUE', '--queue-num 1')

    #block new packets that are not SYN
    block_not_SYN_packets = subprocess.call(cmd, pkt, '-A PREROUTING', '-p tcp', '!', '--syn', '-m conntrack', '--ctstate NEW', '-j NFQUEUE', '--queue-num 1')

    #block Uncommon MMS Values
    block_uncommon_mms_values = subprocess.call(cmd, pkt, '-A PREROUTING', '-p tcp', '-m conntrack', '--ctstate NEW', '-m tcpmss', '!', '--mss 536:65535', '-j NFQUEUE', '--queue-num 1')

    #block packets from private subnets (spoofing)
    block_private_subnets_1 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 224.0.0.0/3', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_2 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 169.254.0.0/16', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_3 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 172.16.0.0/12', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_4 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 192.0.2.0/24', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_5 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 192.168.0.0/16', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_6 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 10.0.0.0/8', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_7 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 0.0.0.0/8', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_8 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 240.0.0.0/5', '-j NFQUEUE', '--queue-num 1')
    block_private_subnets_9 = subprocess.call(cmd, pkt, '-A PREROUTING', '-s 127.0.0.0/8', '!','i', 'lo', '-j NFQUEUE', '--queue-num 1')

    #block ping flood
    block_ping_flood = subprocess.call(cmd, pkt, 'A PREROUTING', '-p icmp', '-j NFQUEUE', '--queue-num 1')
    
    try:
        nfqueue.run()
        return False
    except:
        pass

    return True

def firewall_controller(packet):
    # print("In firewall controller", packet)
    if(firewall_rules_checker(packet)):
        return True
    return False # Packet is malicious
    
    # Steps to be followed as of now
    # Check packet against all firewall rules / firewall_rules_checker
    #   If there's a hit return False
    # Update Packet to the table with all packets
    # Fetch packet data from the table again
    # Check if any hits against another set of firewall rules
    # If there's a hit, update in the firewall table and return False
    # Else return True
