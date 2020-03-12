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
        self.total_data = 0
        self.start_time = 0
        self.end_time = 0
        self.throughput = 0
        self.transactions = []
        self.handshake = False
        return

    def add_transaction(self, transaction):
        """Adds a Transaction to the Flow"""
        self.transactions.append(transaction)
        return

    def handshake_done(self):
        self.handshake = True

    def increase_data(self, amt):
        self.total_data += amt

    def set_start(self, time):
        self.start_time = time

    def set_end(self, time):
        self.end_time = time

    def calculate_throughput(self):
        time = self.end_time - self.start_time
        self.throughput = float(self.total_data) / float(time)

    def __str__(self):
        """String Representation of Flow with first two Transactions"""
        trans_str = ""
        for i in range(2):
            trans_str = trans_str + "Transaction " + str(i + 1) + ":\n" \
                        + str(self.transactions[i]) + "\n"
        return "Flow " + str(self.flow_id) + ": \n" + trans_str + "Throughput: " + str(self.throughput) + " bytes/sec\n"


class Transaction:
    def __init__(self, sent_pkt, recv_pkt=None):
        self.sent_pkt = sent_pkt
        self.recv_pkt = recv_pkt

    def receive_pkt(self, pkt):
        self.recv_pkt = pkt

    def __str__(self):
        return "SENT: " + str(self.sent_pkt) + "\nRECV: " + str(self.recv_pkt)


class Packet:
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
        flag_list.append(FIN)
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
    seq_map = {}
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
            new_flow = Flow(flow_count, src_port, dst_port)
            flow_list.append(new_flow)
            new_flow.set_start(timestamp)
            new_flow.increase_data(len(buffer))
            continue

        current_flow = None
        for flow in flow_list:
            if (flow.sender_port == src_port and flow.receiver_port == dst_port) or (flow.sender_port == dst_port and flow.receiver_port == src_port):
                current_flow = flow
        if current_flow is None:
            continue

        if src_port == current_flow.sender_port:
            current_flow.increase_data(len(buffer))

        if SYN in flags and ACK in flags:
            continue
        elif src_port == current_flow.sender_port and ACK in flags and not current_flow.handshake:
            current_flow.handshake_done()
            continue
        elif src_port == current_flow.sender_port and FIN in flags:
            current_flow.set_end(timestamp)
            current_flow.calculate_throughput()

        seq = buffer[38:42]
        ack = buffer[42:46]
        if src_port == current_flow.sender_port:
            payload_size = len(buffer[66:])
            pkt = Packet(seq, ack)
            transaction = Transaction(pkt)
            seq_map[payload_size + int.from_bytes(seq, "big")] = transaction
            current_flow.add_transaction(transaction)
        elif src_port == current_flow.receiver_port:
            transaction = seq_map.get(int.from_bytes(ack, "big"), None)
            if transaction is None:
                continue
            transaction.receive_pkt(Packet(seq, ack))

    print("Number of Flows: " + str(flow_count) + "\n")
    for i in flow_list:
        print(i)

    file.close()
    return


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
