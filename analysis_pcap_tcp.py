# Justin Santer
# 111501672
# CSE 310 Assignment 2
# March 13, 2020

import dpkt
import sys
# import socket

# CONSTANTS
SENDER_IP = "130.245.145.12"
RECEIVER_IP = "128.208.2.198"
TCP = 0x06
SYN_FLAG = 0x02
ACK_FLAG = 0x10
FIN_FLAG = 0x01


def main(argc, argv):
    if argc == 1:
        file_path = input("Enter the path of the .pcap file: ")
    elif argc > 2:
        print("Invalid Arguments: analysis_pcap_tcp [filepath]")
        return
    else:
        file_path = argv[1]

    analysis_pcap_tcp(file_path)

    return


def analysis_pcap_tcp(file_path):
    flow_count = 0

    file = open(file_path, 'rb')
    pcap = dpkt.pcap.Reader(file)

    for timestamp, buffer in pcap:
        protocol = buffer[23]
        if protocol != TCP:
            continue
        # src = buffer[26:30]
        # dst = buffer[30:34]
        flags = buffer[46:48]
        if flags & SYN_FLAG == SYN_FLAG and flags & ACK_FLAG != ACK_FLAG:
            flow_count += 1

        for i in flags:
            print(hex(i) + " ")

        break

    print(flow_count)

    file.close()
    return


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
