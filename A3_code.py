import pcapy
import socket
from struct import *

# open the network interface for live packet capturing
capture = pcapy.open_live('eth0', 65536, 1, 0)

# loop through captured packets
while True:
    # read the next packet from the interface
    (header, packet) = capture.next()

    # extract the Ethernet header (14 bytes)
    ethernet_header = packet[:14]
    eth_header = unpack('!6s6sH', ethernet_header)
    eth_protocol = socket.ntohs(eth_header[2])

    # extract the IP header (20 bytes)
    if eth_protocol == 8:  # check if the protocol is IP
        ip_header = packet[14:34]
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        # extract the TCP header (20 bytes)
        if protocol == 6:  # check if the protocol is TCP
            tcp_header = packet[14 + iph_length:14 + iph_length + 20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            ack = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            flags = tcph[5]
            window_size = tcph[6]
            checksum = tcph[7]
            urgent_pointer = tcph[8]

            # print packet details
            print('Source IP: {}  , Destination IP: {},   Protocol: {},   Source Port: {},   Destination Port: {},   Flags: {}'.format(
                s_addr,  d_addr,  protocol,  source_port,  dest_port,  flags))
