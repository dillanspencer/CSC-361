# CSC 361 Programming Assignment 2
# Dillan Spencer
# V00914254

import sys

import utils
from utils import ICMP
import connection
from connection import ConnectionType
import struct


def main():
    # Read CAP file
    file_name = sys.argv[1]
    file = open(file_name, "rb")

    # Lists for packets and connections
    packets = []
    connections = {}

    # Read General Header
    data = file.read(24)
    gen_header = load_general_header(data)

    # Read first packet header
    data = file.read(16)
    orig_time = data[0:4]
    orig_micro = data[4:8]
    packet_num = 0
    packets.append(load_packet_header(packet_num, data, orig_time, orig_micro))

    # Read first packet data
    data = file.read(packets[packet_num].incl_len)
    packets[packet_num].Ethernet_header = load_ethernet_header(data)
    packets[packet_num].IP_header = load_ipv4_header(data)
    packets[packet_num].TCP_header = load_tcp_header(data)

    check_connection(packets[packet_num], connections)

    while True:
        try:
            data = file.read(16)
            packet_num += 1
            packets.append(load_packet_header(packet_num, data, orig_time, orig_micro))

            data = file.read(packets[packet_num].incl_len)
            packets[packet_num].Ethernet_header = load_ethernet_header(data)
            packets[packet_num].IP_header = load_ipv4_header(data)
            packets[packet_num].TCP_header = load_tcp_header(data)
            check_connection(packets[packet_num], connections)
        except struct.error as err:
            break

    # Output deliverables
    connection_details(connections)
    file.close()


# Takes a packet and checks what connection it belongs to
# If no connection is found, a new connection is created
# and packet is added to connection.
def check_connection(packet, connections):
    src_ip = packet.IP_header.src_ip
    dst_ip = packet.IP_header.dst_ip
    src_port = packet.TCP_header.src_port
    dst_port = packet.TCP_header.dst_port
    buffer = (src_ip, src_port, dst_ip, dst_port)
    ID = utils.pack_id(buffer)

    # Add connection
    if ID not in connections:
        c = connection.Connection(src_ip, src_port, dst_ip, dst_port)
        c.add_packet(packet)
        connections[ID] = c
    else:
        connections[ID].add_packet(packet)


# Loads data into general header object
# Returns general header
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


# Loads data into packet header object
# Returns packet header
def load_packet_header(packet_num, data, time, micro):
    packet = utils.packet()
    buff1 = data[0:4]
    buff2 = data[4:8]
    incl_len = data[8:12]
    orig_len = data[12:16]

    packet.packet_No_set(packet_num)
    packet.timestamp_set(buff1, buff2, time, micro)
    packet.packet_incl_len_set(incl_len)
    packet.packet_size_set(orig_len)
    packet.buffer = data

    return packet


# Loads data into ethernet header object
# Returns ethernet header
def load_ethernet_header(data):
    header = utils.Ethernet_Header()
    header.set_dest_addr(data[0:6])
    header.set_src_addr(data[6:12])
    header.set_type(data[12:14])
    return header


# Loads data into IPV4 header object
# Returns IPV4 header
def load_ipv4_header(data):
    header = utils.IP_Header()
    src = data[26:30]
    dest = data[30:34]
    total_len = data[16:18]
    header_len = data[14:15]
    ttl = data[22:23]
    protocol = data[23:24]

    header.get_IP(src, dest)
    header.get_total_len(total_len)
    header.get_header_len(header_len)
    header.get_ttl(ttl)
    header.get_protocol(protocol)

    # Check if packet is ICMP and load data from header
    if header.protocol == 1:
        icmp_type = data[34:35]
        icmp_code = data[35:36]
        checksum = data[36:38]
        icmp_data = data[38:]

        header.get_icmp_type(icmp_type)
        header.get_icmp_code(icmp_code)
        header.get_checksum(checksum)
        header.get_icmp_data(icmp_data)

    return header


# Loads data into TCP header object
# Returns TCP header
def load_tcp_header(data):
    header = utils.TCP_Header()
    src_port = data[34:36]
    dest_port = data[36:38]

    header.get_src_port(src_port)
    header.get_dst_port(dest_port)

    return header


# Outputs deliverables of connections
def connection_details(connections):
    sorted_connections = sorted(connections.items(), key=lambda x: x[1].get_hops(connections), reverse=False)
    root = [x[1].root for x in sorted_connections if x[1].get_connection_type() == ConnectionType.INTERMEDIATE]
    print("The IP address of the Source Node: ", root[0][0])
    print("The IP address of the Ultimate Destination Node: ", root[0][1])
    print("The IP addresses of the Intermediate Nodes: ")

    already_printed = []
    count = 1
    for conn in sorted_connections:

        if conn[1].get_connection_type() is ConnectionType.INTERMEDIATE and conn[1].address[0] not in already_printed:
            already_printed.append(conn[1].address[0])
            print("\trouter {0}:".format(count), conn[1].address[0])
            count += 1


if __name__ == '__main__':
    main()
