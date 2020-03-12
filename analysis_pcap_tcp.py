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


class Flow:

    def __init__(self, flow_id, sender_port, receiver_port):
        self.flow_id = flow_id
        self.sender_port = sender_port
        self.receiver_port = receiver_port
        self.total_data = 0
        self.start_time = 0
        self.end_time = 0
        self.throughput = 0
        self.window_scale = 0
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

    def set_window_scale(self, scale):
        self.window_scale = scale

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
    def __init__(self, seq, ack, rwnd):
        self.seq = seq
        self.ack = ack
        self.rwnd = rwnd

    def __str__(self):
        return "SEQ = " + str(self.seq) + ", ACK = " + str(self.ack) + \
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
    """Returns a list of the packet's flags"""
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
    """Runs analysis on PCAP File"""
    # OPEN FILE
    try:
        file = open(file_path, 'rb')
        pcap = dpkt.pcap.Reader(file)
    except FileNotFoundError:
        print("File Not Found")
        return

    # LIST OF FLOWS IN THE PCAP FILE
    flow_list = []

    # MAPS A SEQUENCE NUMBER TO A TRANSACTION
    # USED FOR STORING THE EXPECTED ACK VALUE OF A SENDER PACKET'S ACK RESPONSE
    seq_map = {}

    # LOOPS THROUGH TIMESTAMPS AND BUFFERS OF EACH PACKET IN THE FILE
    for timestamp, buffer in pcap:
        # IF PROTOCOL IS NOT TCP, SKIP PACKET
        protocol = buffer[23]
        if protocol != TCP:
            continue

        # IF SOURCE IP AND DESTINATION IP NOT THE DESIRED VALUES, SKIP PACKET
        src = buffer[26:30]
        dst = buffer[30:34]
        src_str = socket.inet_ntoa(src)
        dst_str = socket.inet_ntoa(dst)
        if src_str != SENDER_IP and src_str != RECEIVER_IP:
            continue
        if dst_str != SENDER_IP and dst_str != RECEIVER_IP:
            continue

        # GETS SOURCE PORT, DEST PORT AND PACKET FLAGS
        src_port = buffer[34:36]
        dst_port = buffer[36:38]
        flags = get_flags(buffer)

        # IF SYN PACKET, CREATE A NEW FLOW
        if SYN in flags and ACK not in flags:
            new_flow = Flow(len(flow_list)+1, src_port, dst_port)
            flow_list.append(new_flow)
            new_flow.set_start(timestamp)
            new_flow.increase_data(len(buffer))
            new_flow.set_window_scale(buffer[73])
            continue

        # GET THE CURRENT FLOW
        current_flow = None
        for flow in flow_list:
            if (flow.sender_port == src_port and flow.receiver_port == dst_port) or (flow.sender_port == dst_port and flow.receiver_port == src_port):
                current_flow = flow
        if current_flow is None:
            continue

        # IF SENDER PACKET, INCREASE THE TOTAL DATA SENT BY SENDER
        if src_port == current_flow.sender_port:
            current_flow.increase_data(len(buffer))

        # PART OF HANDSHAKE, SKIP PACKET
        if SYN in flags and ACK in flags:
            continue
        # ENDS THE HANDSHAKE AND SKIPS
        elif src_port == current_flow.sender_port and ACK in flags and not current_flow.handshake:
            current_flow.handshake_done()
            continue
        # IF FIN PACKET FROM SENDER, CALCULATES THROUGHPUT
        elif src_port == current_flow.sender_port and FIN in flags:
            current_flow.set_end(timestamp)
            current_flow.calculate_throughput()

        # GETS SEQ AND ACK VALUES, CALCULATES RWND
        seq = int.from_bytes(buffer[38:42], "big")
        ack = int.from_bytes(buffer[42:46], "big")
        rwnd = (2 ** current_flow.window_scale) * int.from_bytes(buffer[48:50], "big")

        # IF SENDER, ADD PACKET TO NEW TRANSACTION
        if src_port == current_flow.sender_port:
            payload_size = len(buffer[66:])
            pkt = Packet(seq, ack, rwnd)
            transaction = Transaction(pkt)
            seq_map[payload_size + seq] = transaction
            current_flow.add_transaction(transaction)
        # IF RECEIVER, ADD PACKET TO CORRESPONDING TRANSACTION USING MAP
        elif src_port == current_flow.receiver_port:
            transaction = seq_map.get(ack, None)
            if transaction is None:
                continue
            transaction.receive_pkt(Packet(seq, ack, rwnd))

    # PRINT RESULTS
    print("Number of Flows: " + str(len(flow_list)) + "\n")
    for i in flow_list:
        print(i)

    # CLOSE FILE AND RETURN
    file.close()
    return


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
