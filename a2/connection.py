import utils


class Connection:
    address = None
    packets = None
    flags = None
    packets_sent = None
    bytes_sent = None
    ID = None

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.address = (src_ip, src_port, dst_ip, dst_port)
        self.packets = []
        self.ID = utils.pack_id(self.address)
        self.packets_sent = {}
        self.bytes_sent = {}
        self.flags = {}

    # Adds packet to list
    # Checks packet flags and handles connection status
    def add_packet(self, packet):
        self.packets.append(packet)
        self.check_flags(packet)
        self.check_packet_sent(packet)

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

    # Checks if FIN flag was set at any point in the connection
    def is_connection_finished(self):
        return self.flags["FIN"] > 0

    # Calculates the total connection time
    # returns a 3-tuple, start time, end time, and total time
    def get_connection_time(self):
        startTime = self.packets[0].timestamp
        endTime = self.packets[len(self.packets) - 1].timestamp
        return startTime, endTime, endTime - startTime

    # returns number of packets sent by src
    def get_src_packet_total(self):
        return self.packets_sent[self.address[0]]

    # return number of packets sent by dst
    def get_dst_packet_total(self):
        return self.packets_sent[self.address[2]]

    # returns total number of packets sent
    def get_num_packets(self):
        return len(self.packets)
