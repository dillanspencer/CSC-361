import sys
import utils
import connection
import struct


def main():
    file_name = sys.argv[1]
    file = open(file_name, "rb")
    packets = []
    connections = {}

    data = file.read(24)
    gen_header = load_general_header(data)

    data = file.read(16)
    orig_time = data[0:4]
    packet_num = 0

    packets.append(load_packet_header(packet_num, data, orig_time))

    data = file.read(packets[packet_num].incl_len)
    packets[packet_num].Ethernet_header = load_ethernet_header(data)
    packets[packet_num].IP_header = load_ipv4_header(data)
    packets[packet_num].TCP_header = load_tcp_header(data)
    check_connection(packets[packet_num], connections)

    while True:
        try:
            print("------------")
            data = file.read(16)
            packet_num += 1
            packets.append(load_packet_header(packet_num, data, orig_time))

            data = file.read(packets[packet_num].incl_len)
            packets[packet_num].Ethernet_header = load_ethernet_header(data)
            packets[packet_num].IP_header = load_ipv4_header(data)
            packets[packet_num].TCP_header = load_tcp_header(data)
            check_connection(packets[packet_num], connections)
        except struct.error as e:
            break


def check_connection(packet, connections):
    src_ip = packet.IP_header.src_ip
    dst_ip = packet.IP_header.dst_ip
    src_port = packet.TCP_header.src_port
    dst_port = packet.TCP_header.dst_port
    buffer = (src_ip, src_port, dst_ip, dst_port)
    ID = utils.pack_id(buffer)

    print("SRC IP: ", src_ip, "SRC PORT: ", src_port)
    print("DST IP: ", dst_ip, "DST PORT: ", dst_port)
    print("ID: ", ID)

    if ID not in connections:
        print("ID not found in connections...")
        print("Creating new connection!")
        c = connection.Connection(src_ip, src_port, dst_ip, dst_port)
        c.add_packet(packet)
        connections[ID] = c
    else:
        connections[ID].add_packet(packet)


def load_general_header(data):
    gen_header = utils.General_Header()
    gen_header.set_magic_number(data[0:4])
    gen_header.set_version_major(data[4:6])
    gen_header.set_version_minor(data[6:8])
    gen_header.set_zone(data[8:12])
    gen_header.set_sigfigs(data[12:16])
    gen_header.set_snaplen(data[16:20])
    gen_header.set_network(data[20:24])
    return gen_header


def load_packet_header(packet_num, data, time):
    packet = utils.packet()
    buff1 = data[0:4]
    buff2 = data[4:8]
    incl_len = data[8:12]
    orig_len = data[12:16]

    packet.packet_No_set(packet_num)
    packet.timestamp_set(buff1, buff2, time)
    packet.packet_incl_len_set(incl_len)
    packet.packet_size_set(orig_len)
    packet.buffer = data

    print("TIME: ", packet.timestamp)
    print("INCL_LEN: ", packet.incl_len)
    print("SIZE: ", packet.size)
    return packet


def load_ethernet_header(data):
    header = utils.Ethernet_Header()
    header.set_dest_addr(data[0:6])
    header.set_src_addr(data[6:12])
    header.set_type(data[12:14])
    print("Destination MAC: ", header.dest_addr)
    print("Source MAC: ", header.src_addr)
    print("Eth Type: ", header.type)
    return header


def load_ipv4_header(data):
    header = utils.IP_Header()
    src = data[26:30]
    dest = data[30:34]
    total_len = data[16:18]
    header_len = data[14:15]

    header.get_IP(src, dest)
    header.get_total_len(total_len)
    header.get_header_len(header_len)

    # print("SRC: ", header.src_ip)
    # print("DEST: ", header.dst_ip)
    # print("Total Length: ", header.total_len)
    # print("Header Length: ", header.ip_header_len)

    return header


def load_tcp_header(data):
    header = utils.TCP_Header()
    src_port = data[34:36]
    dest_port = data[36:38]
    seq_num = data[38:42]
    ack_num = data[42:46]
    data_offset = data[46:47]
    flags = data[47:48]
    w1 = data[48:49]
    w2 = data[49:50]

    header.get_src_port(src_port)
    header.get_dst_port(dest_port)
    header.get_seq_num(seq_num)
    header.get_ack_num(ack_num)
    header.get_data_offset(data_offset)
    header.get_window_size(w1, w2)
    header.get_flags(flags)

    # print("SRC: ", header.src_port)
    # print("DEST: ", header.dst_port)
    # print("SEQ: ", header.seq_num)
    # print("ACK: ", header.ack_num)
    # print("DATA OFFSET: ", header.data_offset)
    # print("WINDOW SIZE: ", header.window_size)
    # print("FLAGS: ", header.flags)

    return header


if __name__ == '__main__':
    main()
