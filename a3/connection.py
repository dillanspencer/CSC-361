# CSC 361 Programming Assignment 2
# Dillan Spencer
# V00914254

from enum import Enum
import utils
from utils import Protocol
from utils import ICMP


class ConnectionType(Enum):
    ROOT = 0
    INTERMEDIATE = 1
    OTHER = 2


class Connection:
    root = None
    connection_type = None
    address = None
    packets = None
    framented_packets = None
    flags = None
    state = None
    packets_sent = None
    bytes_sent = None
    start_time = None
    end_time = None
    total_window = None
    min_window = None
    max_window = None
    rtt_values = None
    icmp_flag = False
    ID = None
    parent_address = None
    parent_id = None
    connections = None

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.root = None
        self.address = (src_ip, src_port, dst_ip, dst_port)
        self.packets = []
        self.fragmented_packets = []
        self.ID = utils.pack_id(self.address)
        self.parent_id = None
        self.parent_address = None
        self.packets_sent = {}
        self.bytes_sent = {}
        self.flags = {}
        self.state = "S0F0"
        self.ttl = float("inf")
        self.start_time = float("inf")
        self.end_time = float("-inf")
        self.total_window = 0
        self.min_window = float("inf")
        self.max_window = float("-inf")
        self.rtt_values = []
        self.connections = {}

    # Adds packet to list
    # Checks packet flags and handles connection status
    # We only want UDP and ICMP packets so filter out the rest
    def add_packet(self, packet):
        # if packet is other than UDP or ICMP then don't add it
        if packet.IP_header.protocol == Protocol.UDP.value or packet.IP_header.protocol == Protocol.ICMP.value:
            self.packets.append(packet)
            self.check_icmp(packet)
            if packet.IP_header.protocol == Protocol.ICMP.value and packet.IP_header.icmp_type in ICMP.ALL.value:
                self.check_hops(packet)
            self.check_connection_type()

            # self.check_flags(packet)
            # self.check_packet_sent(packet)
            # self.check_packet_time(packet)
            # self.check_window_size(packet)

    # Checks if the packet was sent or received from the source node
    # or from the ultimate destination. Will also find if the connection
    # is from an intermediate router.
    def check_connection_type(self):
        if self.root is None:
            return
        if self.root[0] in self.address and self.root[1] in self.address:
            self.connection_type = ConnectionType.ROOT
        elif self.root[0] in self.address and self.root[1] not in self.address and self.icmp_flag:
            self.connection_type = ConnectionType.INTERMEDIATE
        else:
            self.connection_type = ConnectionType.OTHER

    # Checks all bits of flags and increment the flag dictionary
    def check_flags(self, packet):
        try:
            self.flags["ACK"] += packet.TCP_header.flags["ACK"]
            self.flags["RST"] += packet.TCP_header.flags["RST"]
            self.flags["SYN"] += packet.TCP_header.flags["SYN"]
            self.flags["FIN"] += packet.TCP_header.flags["FIN"]
        except KeyError:
            self.flags["ACK"] = packet.TCP_header.flags["ACK"]
            self.flags["RST"] = packet.TCP_header.flags["RST"]
            self.flags["SYN"] = packet.TCP_header.flags["SYN"]
            self.flags["FIN"] = packet.TCP_header.flags["FIN"]

    # Counts how many packets have been sent by src and dst
    # Counts how many bytes have been sent by src and dst
    def check_packet_sent(self, packet):
        key = packet.IP_header.src_ip
        try:
            self.packets_sent[key] += 1
            self.bytes_sent[key] += packet.get_payload()
        except KeyError:
            self.packets_sent[key] = 1
            self.bytes_sent[key] = packet.get_payload()

    # Calculates the min and max time of connection
    def check_packet_time(self, packet):
        if packet.TCP_header.flags["SYN"] == 1 and packet.TCP_header.flags["ACK"] == 0:
            self.start_time = min(packet.timestamp, self.start_time)
        if packet.TCP_header.flags["FIN"] == 1 and packet.TCP_header.flags["ACK"] == 1:
            self.end_time = max(packet.timestamp, self.end_time)

    # Calculates the min and max window size of Connection
    def check_window_size(self, packet):
        self.total_window += packet.TCP_header.window_size
        self.min_window = min(packet.TCP_header.window_size, self.min_window)
        self.max_window = max(packet.TCP_header.window_size, self.max_window)

    def check_icmp(self, packet):
        if packet.IP_header.protocol == Protocol.ICMP.value:
            self.icmp_flag = True

    # Checks if FIN flag was set at any point in the connection
    def is_connection_finished(self):
        return self.flags["FIN"] > 0

    # checks and formats the state of the connection
    def check_connection_state(self):
        ack = self.flags["ACK"]
        rst = self.flags["RST"]
        syn = self.flags["SYN"]
        fin = self.flags["FIN"]

        self.state = "S" + str(syn) + "F" + str(fin)

        if rst > 0:
            self.state += "/R"
        return self.state

    # Calculates RTT between SRC and DST
    # Matches packets from SRC with its ACK packet from DST
    # Returns a list of all rtt times for this connection
    def calculate_rtt(self):
        total_rtt = 0
        for packet in self.packets:
            parent_connection = self.connections[packet.parent]
            start_time = parent_connection.packets[0].timestamp
            end_time = packet.timestamp
            elapsed_time = end_time - start_time
            total_rtt += elapsed_time
        self.rtt_values = total_rtt / len(self.packets)
        return self.rtt_values

    def check_hops(self, packet):
        trigger = utils.packet()
        data = packet.IP_header.icmp_data
        ttl = data[12:13]
        src = data[16:20]
        dst = data[20:24]
        src_port = data[24:26]
        dst_port = data[26:28]

        trigger.IP_header.get_IP(src, dst)
        trigger.TCP_header.get_src_port(src_port)
        trigger.TCP_header.get_dst_port(dst_port)
        trigger.IP_header.get_ttl(ttl)
        self.root = (trigger.IP_header.src_ip, trigger.IP_header.dst_ip)
        self.parent_id = utils.pack_id((trigger.IP_header.src_ip, trigger.TCP_header.src_port, trigger.IP_header.dst_ip,
                                        trigger.TCP_header.dst_port))
        self.ttl = trigger.IP_header.ttl + 1
        packet.packet_parent_set(self.parent_id)

    def get_hops(self, connections):
        if self.connection_type != ConnectionType.INTERMEDIATE:
            return 0
        parent = connections[self.parent_id]
        self.connections = connections
        return parent.get_packet_number() + self.ttl

    # returns if this is a complete connection
    def is_complete(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] > 0

    # returns if connection was reset
    def is_reset(self):
        return self.flags["RST"] > 0

    # returns if connection was still open when trace ended
    def is_open(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] == 0

    # returns packet number for ttl
    def get_packet_number(self):
        return self.packets[0].packet_No

    # Calculates the total connection time
    # returns a 3-tuple, start time, end time, and total time
    def get_connection_time(self):
        if self.end_time == float('-inf'):
            self.end_time = self.packets[len(self.packets) - 1].timestamp
        return self.start_time, self.end_time, self.end_time - self.start_time

    # returns number of packets sent by src
    def get_src_packet_total(self):
        return self.packets_sent[self.address[0]]

    # return number of packets sent by dst
    def get_dst_packet_total(self):
        try:
            return self.packets_sent[self.address[2]]
        except KeyError:
            return 0

    # returns total bytes sent by src
    def get_src_bytes_total(self):
        return self.bytes_sent[self.address[0]]

    # returns total bytes sent by dst
    def get_dst_bytes_total(self):
        try:
            return self.bytes_sent[self.address[2]]
        except KeyError:
            return 0

    # returns total number of bytes sent in connection
    def get_num_bytes(self):
        try:
            return self.bytes_sent[self.address[0]] + self.bytes_sent[self.address[2]]
        except KeyError:
            return 0

    # returns number of rtt pairs in connection
    def get_num_rtt_pairs(self):
        return len(self.rtt_values)

    # returns total number of packets sent
    def get_num_packets(self):
        return len(self.packets)

    # returns connection type of the connection
    def get_connection_type(self):
        return self.connection_type
