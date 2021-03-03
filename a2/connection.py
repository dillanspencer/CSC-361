import utils


class Connection:
    address = None
    packets = None
    flags = None
    state = None
    packets_sent = None
    bytes_sent = None
    start_time = None
    end_time = None
    total_window = None
    min_window = None
    max_window = None
    ID = None

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.address = (src_ip, src_port, dst_ip, dst_port)
        self.packets = []
        self.ID = utils.pack_id(self.address)
        self.packets_sent = {}
        self.bytes_sent = {}
        self.flags = {}
        self.state = "S0F0"
        self.start_time = float("inf")
        self.end_time = float("-inf")
        self.total_window = 0
        self.min_window = float("inf")
        self.max_window = float("-inf")

    # Adds packet to list
    # Checks packet flags and handles connection status
    def add_packet(self, packet):
        self.packets.append(packet)
        self.check_flags(packet)
        self.check_packet_sent(packet)
        self.check_packet_time(packet)
        self.check_window_size(packet)

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
            self.bytes_sent[key] += packet.size
        except KeyError:
            self.packets_sent[key] = 1
            self.bytes_sent[key] = packet.size

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
            self.state += "/R" + str(rst)
        return self.state

    # returns if this is a complete connection
    def is_complete(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] > 0

    # returns if connection was reset
    def is_reset(self):
        return self.flags["RST"] > 0

    # returns if connection was still open when trace ended
    def is_open(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] == 0

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
        return self.packets_sent[self.address[2]]

    def get_src_bytes_total(self):
        return self.bytes_sent[self.address[0]]

    def get_dst_bytes_total(self):
        return self.bytes_sent[self.address[2]]

    def get_min_rtt(self):
        return min(self.rtt_packets)

    def get_num_bytes(self):
        return self.bytes_sent[self.address[0]] + self.bytes_sent[self.address[2]]

    # returns total number of packets sent
    def get_num_packets(self):
        return len(self.packets)
