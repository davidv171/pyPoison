# pyPoison
Is a simple application/program showing you how to perform a "Man in the Middle ARP poisoning" attack using Scapy.

To make it work you simply input the target IP and gateway IP and the program does the rest for you. 

Since the comments are in Slovenian, this is how it works:
- get MAC address of the default gateway and target computer(function pridobi_mac)
- send an ARP request telling your gateway that you're the target PC 
- send an ARP request telling the target PC you're the gateway
This updates both of their ARP tables, making all their communication to each other visible to you. 
Most modern networks are protected against this. 

The program saves all the recorded data to a python.pcap file, that is easily readable by Wireshark or a similar program. 
