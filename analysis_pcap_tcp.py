# Justin Santer
# 111501672
# CSE 310 Assignment 2
# March 13, 2020

import dpkt
import sys
import socket

# CONSTANTS
SENDER_IP = "130.245.145.12"
RECEIVER_IP = "128.208.2.198"
TCP = 0x06
FIN_FLAG = 0x01
FIN = "FIN"
SYN_FLAG = 0x02
SYN = "SYN"
RST_FLAG = 0x04
RST = "RST"
PSH_FLAG = 0x08
PSH = "PSH"
ACK_FLAG = 0x10
ACK = "ACK"

# GLOBAL FLOW COUNT
flow_count = 0


class Flow:
    def __init__(self, flow_id, sender_port, receiver_port):
        self.flow_id = flow_id
        self.sender_port = sender_port
        self.receiver_port = receiver_port
        self.throughput = 0
        self.transactions = []
        return

    def add_transaction(self, transaction):
        """Adds a Transaction to the Flow"""
        self.transactions.append(transaction)
        return

    def __str__(self):
        """String Representation of Flow with first two Transactions"""
        trans_str = ""
        for i in range(2):
            trans_str = trans_str + "Transaction " + str(i + 1) + ": " \
                        + str(self.transactions[i]) + "\n"
        return "Flow " + str(self.flow_id) + ": \n" + trans_str + "Throughput: " + str(self.throughput) + "\n"


class Transaction:
    def __init__(self, seq, ack, rwnd=0):
        self.seq = seq
        self.ack = ack
        self.rwnd = rwnd

    def __str__(self):
        return "SEQ = " + str(int.from_bytes(self.seq, "big")) + ", ACK = " + str(int.from_bytes(self.ack, "big")) + \
               ", RWND = " + str(self.rwnd)


def main(argc, argv):
    if argc == 1:
        # file_path = input("Enter the path of the .pcap file: ")
        file_path = "assignment2.pcap"
    elif argc > 2:
        print("Invalid Arguments: analysis_pcap_tcp [filepath]")
        return
    else:
        file_path = argv[1]

    analysis_pcap_tcp(file_path)

    return


def get_flags(buffer):
    flag = buffer[47]
    flag_list = []
    if flag & FIN_FLAG == FIN_FLAG:
        flag_list.append(ACK)
    if flag & SYN_FLAG == SYN_FLAG:
        flag_list.append(SYN)
    if flag & RST_FLAG == RST_FLAG:
        flag_list.append(RST)
    if flag & PSH_FLAG == PSH_FLAG:
        flag_list.append(RST)
    if flag & ACK_FLAG == ACK_FLAG:
        flag_list.append(ACK)

    return flag_list


def analysis_pcap_tcp(file_path):
    file = open(file_path, 'rb')
    pcap = dpkt.pcap.Reader(file)

    global flow_count
    flow_list = []
    # pkt_amt = 0
    for timestamp, buffer in pcap:
        protocol = buffer[23]
        if protocol != TCP:
            continue

        src = buffer[26:30]
        dst = buffer[30:34]
        src_str = socket.inet_ntoa(src)
        dst_str = socket.inet_ntoa(dst)
        if src_str != SENDER_IP and src_str != RECEIVER_IP:
            continue
        if dst_str != SENDER_IP and dst_str != RECEIVER_IP:
            continue

        src_port = buffer[34:36]
        dst_port = buffer[36:38]

        flags = get_flags(buffer)
        if SYN in flags and ACK not in flags:
            flow_count += 1
            flow_list.append(Flow(flow_count, src_port, dst_port))
            continue
        elif SYN in flags and ACK in flags:
            continue

        current_flow = None
        for flow in flow_list:
            if (flow.sender_port == src_port and flow.receiver_port == dst_port) or (flow.sender_port == dst_port and flow.receiver_port == src_port):
                current_flow = flow
        if current_flow is None:
            continue

        seq = buffer[38:42]
        ack = buffer[42:46]
        current_flow.add_transaction(Transaction(seq, ack))

    print("Number of Flows: " + str(flow_count) + "\n")
    for i in flow_list:
        print(i)

    file.close()
    return


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
