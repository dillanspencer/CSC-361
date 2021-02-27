import utils


class Connection:
    packets = None
    flags = None
    ID = None

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.address = (src_ip, src_port, dst_ip, dst_port)
        self.packets = []
        self.ID = utils.pack_id(self.address)
        self.flags = {}

    # Adds packet to list
    # Checks packet flags and handles connection status
    def add_packet(self, packet):
        self.packets.append(packet)
        self.check_flags(packet)
        print(self.flags)

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

    def is_connection_finished(self):
        return self.flags["FIN"] > 0
