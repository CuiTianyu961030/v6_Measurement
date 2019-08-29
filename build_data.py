# import scapy
from scapy.all import *
import scapy.all as scapy
# from scapy.layers import http

# packeges = scapy.rdpcap('C:\\Users\\dell-pc\\Desktop\\live.pcap')
# print(packeges)
#f = open("log.txt", "w")
nh_dict = {}
hopbyhop_list = []
try:
    pkts = PcapReader("C:\\Users\\dell-pc\\Desktop\\center_ipv6.pcap")
    #pkts = PcapReader("E:\\center_ipv6.pcap")
    count = -1
    while count != 0:
        pkts_dpkt = pkts.read_packet()
        if pkts_dpkt is None:
            break
        else:
            #print(repr(pkts_dpkt))
            if "nh=" in str(repr(pkts_dpkt)):
                next_header = str(repr(pkts_dpkt)).split("nh=")[1].split(" ")[0]
                if next_header not in nh_dict.keys():
                    nh_dict[next_header] = 1
                else:
                    nh_dict[next_header] = nh_dict[next_header] + 1
                if next_header == "Hop-by-Hop":
                    hopbyhop_list.append(str(repr(pkts_dpkt)))
            print(nh_dict)

            #f.write(repr(pkts_dpkt) + "\n")
            #print(str(repr(pkts_dpkt)).split("nh=")[1].split(" ")[0])
except Scapy_Exception as e:
    print(e)

print(hopbyhop_list)
#f.close()