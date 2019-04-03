from scapy.all import *

# Our packet callback
def packet_callback(packet):
    print (packet.show())

# Fire up our sniifer
sniff(prn=packet_callback, count=1)
