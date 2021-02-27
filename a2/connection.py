import utils


class Connection:
    packets = None
    ID = None

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.address = (src_ip, src_port, dst_ip, dst_port)
        self.packets = []
        self.ID = utils.pack_id(self.address)

    # Adds packet to list
    # Checks packet flags and handles connection status
    def add_packet(self, packet):
        self.packets.append(packet)
