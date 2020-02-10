# firewall
Implementation of a dynamic rules updation for a firewall

Modules

1. Controller which starts all other modules simultaneously
2. Sniffer to sniff packets
3. Trigger module running while sniffing packets
    - first layer - traffic based trigger
    - second layer - packet based trigger
    - call dynamic firewall
4. Dynamic firewall - to dynamically add rules to firewall being used