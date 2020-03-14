# firewall
Implementation of a dynamic rules updation for a firewall to counter ddos

Modules
1. Controller which starts all other modules simultaneously
    - controller.py
2. Sniffer 
    - to sniff packets
    - sniffer.py
3. Trigger module running while sniffing packets
    - first layer - traffic based trigger 
        - traffictrigger.py
    - second layer - packet based trigger 
        - packetfilter.py
4. Dynamic firewall
    - to dynamically add rules to firewall being used 
    - firewall.py
5. Packet Filter
    - to check for a packet validity
    - firewall.py
6. Redirection 
    - to send the packet to the honeypot or otherwise
    - forwarder.py

How will it work?
1. Start a lot of sniffers on each core.
2. Start the trigger module which maintains 
    a count of all the number of incoming request 
    and requests per time interval.
3. Start the second trigger module - 
    layer 2 of packet filtering that examines each packet and returns the
    response indicating - attack or not.
3. Start the firewall changer module that acts like a server
    taking a request to block all kinds of packets when a particular
    one is sent to it.
4. Start the forwarding module that takes the packet from sniffer and
    accordingly sends it.
5. Above processes must be started at minimal time delay.
6. Use IPC to communicate between processes.

How will the flow work(for attack)?
1. Packets arrive
2. Sniff the packets
3. Check for firewall rule
    Call the forwarding module accordingly
4. Keep informing trigger 1 of the count
5. When there is a traffic based trigger,
    indicate the forwarding module to stop there
    and let the second trigger take charge.
6. Second trigger will execute all the rules to check
    for a malicious packet.
    If malicious call the firewall module to update rule
7. Accordingly call the forwarding module from second trigger
